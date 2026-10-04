"""The capture engine: interface discovery and a stoppable sniffer thread.

Threading contract
------------------
Tkinter may only be touched from the thread that created the root window. The
previous implementation called ``root.after()`` from inside the sniffing thread,
which is undefined behaviour in Tk.

The rule here instead:

    * the capture thread does exactly one thing -- decode a frame and put it on
      a ``queue.Queue``. It never touches the UI.
    * the UI thread drains the queue on a timer via ``after()``.

That keeps scapy's blocking C call off the UI thread while leaving all widget
access on the main thread.
"""

from __future__ import annotations

import contextlib
import queue
import threading
import time
from dataclasses import dataclass, field

import scapy.config
from scapy.arch import compile_filter
from scapy.error import Scapy_Exception
from scapy.sendrecv import sniff

from .decode import decode
from .models import Alert, PacketRecord

DEFAULT_QUEUE_SIZE = 10_000
DRAIN_INTERVAL_MS = 100
MAX_BATCH = 500


def list_interfaces() -> list[str]:
    """Return usable capture interface names.

    ``conf.ifaces`` includes loopback entries that cannot be captured on some
    platforms, so anything without an address is filtered out. Never raises:
    interface discovery failing should show an empty list in the UI, not a
    traceback dialog.
    """
    names: list[str] = []
    try:
        for name, iface in scapy.config.conf.ifaces.items():
            if name is None:
                continue
            if getattr(iface, "ip", None) or getattr(iface, "mac", None):
                names.append(str(name))
    except Exception:
        # Enumeration itself failed (netlink down, no libpcap). Offer loopback so
        # the UI still has something selectable rather than an empty dropdown.
        return ["lo"]
    return sorted(set(names)) or ["lo"]


def validate_bpf(expression: str) -> str:
    """Check a BPF filter by compiling it against libpcap's grammar.

    Returns the normalised expression, or raises ``ValueError`` with a message
    the UI can show verbatim. Doing this up front means an invalid filter
    reports immediately instead of killing the capture thread silently.
    """
    expression = (expression or "").strip()
    if not expression:
        return ""

    try:
        compiled = compile_filter(expression)
    except Exception as error:
        raise ValueError(f"invalid BPF filter: {error}") from error

    if compiled is None:
        raise ValueError("libpcap rejected the filter expression")

    return expression


@dataclass(slots=True)
class CaptureStats:
    """Capture-side counters, kept separate from TrafficStats (traffic counters)."""

    packets_seen: int = 0
    decode_failures: int = 0
    packets_dropped: int = 0
    started_at: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def elapsed(self) -> float:
        return max(time.time() - self.started_at, 0.0) if self.started_at else 0.0

    @property
    def loss_ratio(self) -> float:
        """Fraction of seen packets the UI never received."""
        total = self.packets_seen
        return self.packets_dropped / total if total else 0.0


class CaptureEngine:
    """Runs a scapy sniffer on a background thread and publishes decoded packets.

    Usage from any UI thread::

        engine = CaptureEngine(iface="eth0", bpf="tcp port 443")
        engine.start()
        while running:
            for record, alerts in engine.drain():
                table.insert("", "end", values=record.table_row())
            root.after(100, pump)
        engine.stop()
    """

    def __init__(
        self,
        iface: str | None = None,
        bpf: str = "",
        count: int = 0,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        store: bool = False,
        stats=None,
        detector=None,
        keep_raw: bool = True,
    ) -> None:
        self.iface = iface
        self.bpf = bpf or ""
        self.count = count
        self.store = store
        # Analyzers run on the capture thread on purpose. Detection is regex
        # and counter work; doing it on the Tk thread would make the window
        # stutter under load. The UI thread should only insert widgets.
        self.stats = stats
        self.detector = detector
        # Serialising each frame costs real throughput (see bench.py). It stays
        # on by default so a live capture can be exported to pcap.
        self.keep_raw = keep_raw

        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._index = 0
        self.detector_failures = 0
        self.capture_stats = CaptureStats()

    # --- lifecycle ------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Begin capturing. Raises ``ValueError`` if the BPF filter is invalid."""
        if self.is_running:
            return

        self.bpf = validate_bpf(self.bpf)

        self._stop.clear()
        self.capture_stats = CaptureStats(started_at=time.time())
        self._thread = threading.Thread(
            target=self._run, name="pktanalyzer-capture", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Ask the sniffer to finish and wait briefly for the thread to exit."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._thread = None

    def __enter__(self) -> CaptureEngine:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    # --- producer (runs on the capture thread) --------------------------

    def _handle(self, packet: object) -> None:
        if self._stop.is_set():
            return

        # Decoding and analysis are independent stages. A broken detection rule
        # must never cost us an already-decoded packet, so they get separate
        # guards instead of sharing one try block.
        try:
            record = decode(packet, self._index, keep_raw=self.keep_raw)  # type: ignore[arg-type]
        except Exception as error:  # a malformed frame must not kill the thread
            self.capture_stats.errors.append(f"decode failed: {error}")
            self.capture_stats.decode_failures += 1
            return

        self._index += 1
        self.capture_stats.packets_seen += 1

        alerts: list[Alert] = []
        if self.stats is not None:
            try:
                self.stats.observe(record)
            except Exception as error:
                self.capture_stats.errors.append(f"stats failed: {error}")

        if self.detector is not None:
            try:
                alerts = self.detector.inspect(record)
                if alerts and self.stats is not None:
                    self.stats.alert_count += len(alerts)
            except Exception as error:
                self.capture_stats.errors.append(f"detector failed: {error}")
                self.detector_failures += 1

        # block=False keeps a slow UI from stalling the capture; dropping is
        # preferable to unbounded memory growth, and the drop is counted.
        try:
            self._queue.put_nowait((record, tuple(alerts)))
        except queue.Full:
            self.capture_stats.packets_dropped += 1

    def _run(self) -> None:
        try:
            sniff(
                prn=self._handle,
                iface=self.iface,
                filter=self.bpf or None,
                count=self.count,
                store=self.store,
                stop_filter=lambda _: self._stop.is_set(),
            )
        except Scapy_Exception as error:
            # Missing Npcap/libpcap or insufficient privileges land here.
            self.capture_stats.errors.append(f"capture failed: {error}")
        except PermissionError as error:
            self.capture_stats.errors.append(
                f"permission denied: raw capture needs root or CAP_NET_RAW ({error})"
            )
        except OSError as error:
            self.capture_stats.errors.append(f"capture failed: {error}")
        except Exception as error:
            self.capture_stats.errors.append(f"unexpected capture error: {error}")

    # --- consumer (must be called from the UI thread) -------------------

    def drain(self, max_items: int = MAX_BATCH) -> tuple[list[PacketRecord], list[Alert]]:
        """Pull up to ``max_items`` pending packets without blocking.

        The batch cap keeps a burst from starving the Tk event loop: draining
        50,000 rows in one go would freeze the window for seconds.
        """
        records: list[PacketRecord] = []
        alerts: list[Alert] = []
        for _ in range(max_items):
            try:
                record, packet_alerts = self._queue.get_nowait()
            except queue.Empty:
                break
            records.append(record)
            # The queue holds one alert *bundle* per packet; flatten it, or the
            # caller receives tuples where it expects Alert objects.
            alerts.extend(packet_alerts)
        return records, alerts

    @property
    def pending(self) -> int:
        return self._queue.qsize()


def replay(packets: list, keep_raw: bool = True) -> list[PacketRecord]:
    """Decode pre-built packets with no sniffing involved.

    Used by the test suite and useful for demoing the UI on a machine where the
    user lacks capture privileges. Keeps raw frames by default so the result is
    exportable to pcap, unlike a live capture with retention disabled.
    """
    records = []
    for index, packet in enumerate(packets):
        with contextlib.suppress(Exception):
            packet.time = time.time()
        records.append(decode(packet, index, keep_raw=keep_raw))
    return records
