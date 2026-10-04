"""Rolling traffic statistics.

Design constraint: ``observe()`` must be O(1) amortised. The previous GUI
redrew every packet on a timer, which is O(n) per refresh and O(n^2) over a
capture. Here the rate window is a single ``deque(maxlen=...)`` of
``(timestamp, length)`` pairs, so memory is bounded by configuration rather
than by capture length, and insertion is constant time.

Keeping timestamps and lengths in one deque (rather than two parallel deques)
matters: pruning one deque independently would silently mis-align the pair.
"""

from __future__ import annotations

import contextlib
import time
from collections import Counter, deque
from dataclasses import dataclass, field

from .models import PacketRecord

PPS_WINDOW = 10.0
MAX_WINDOW_SAMPLES = 50_000
TOP_N = 5


@dataclass(slots=True)
class TrafficSnapshot:
    """Immutable view of the counters, safe to hand to the UI thread."""

    total_packets: int
    total_bytes: int
    duration: float
    packets_per_second: float
    bytes_per_second: float
    avg_packet_size: int
    unique_hosts: int
    by_protocol: dict[str, int] = field(default_factory=dict)
    top_sources: list[tuple[str, int]] = field(default_factory=list)
    top_destinations: list[tuple[str, int]] = field(default_factory=list)
    top_ports: list[tuple[int, int]] = field(default_factory=list)
    active_alerts: int = 0


class TrafficStats:
    """Accumulates counters over a capture. Feed every decoded packet to ``observe``."""

    def __init__(self, pps_window: float = PPS_WINDOW, max_samples: int = MAX_WINDOW_SAMPLES) -> None:
        self._pps_window = pps_window
        self._window: deque[tuple[float, int]] = deque(maxlen=max_samples)
        self._by_protocol: Counter[str] = Counter()
        self._by_source: Counter[str] = Counter()
        self._by_destination: Counter[str] = Counter()
        self._by_port: Counter[int] = Counter()
        self._hosts: set[str] = set()

        self.total_packets = 0
        self.total_bytes = 0
        self.started_at: float | None = None
        self.last_seen: float | None = None
        self.alert_count = 0

    # --- ingestion ------------------------------------------------------

    def observe(self, record: PacketRecord) -> None:
        """Fold one packet into every counter.

        Swallows its own errors on purpose: a statistics failure must never
        take down the capture thread.
        """
        with contextlib.suppress(Exception):
            self.observe_many([record])

    def observe_many(self, records: list[PacketRecord]) -> None:
        for record in records:
            stamp = record.timestamp
            if self.started_at is None:
                self.started_at = stamp
            self.last_seen = stamp

            self.total_packets += 1
            self.total_bytes += record.length
            self._window.append((stamp, record.length))

            if record.protocol:
                self._by_protocol[record.protocol] += 1
            if record.src_ip:
                self._by_source[record.src_ip] += 1
                self._hosts.add(record.src_ip)
            if record.dst_ip:
                self._by_destination[record.dst_ip] += 1
                self._hosts.add(record.dst_ip)
            if record.dst_port is not None:
                self._by_port[record.dst_port] += 1

    # --- queries --------------------------------------------------------

    def _prune(self, now: float) -> list[tuple[float, int]]:
        """Drop samples older than the window and return what remains.

        Entries are appended in capture order, so the stale ones are always a
        prefix and can be dropped from the left in amortised O(1).
        """
        cutoff = now - self._pps_window
        window = self._window
        while window and window[0][0] < cutoff:
            window.popleft()
        return list(window)

    def _elapsed(self, now: float) -> float:
        """Seconds to divide by. Uses the real elapsed time during warm-up."""
        if self.started_at is None:
            return self._pps_window
        elapsed = now - self.started_at
        # Before the window fills, dividing by the full window would report an
        # artificially low rate, so divide by the time actually observed.
        return min(elapsed, self._pps_window) if elapsed > 0 else 1e-6

    def packets_per_second(self, now: float | None = None) -> float:
        """Packet rate over the trailing window, not a lifetime average."""
        now = now if now is not None else (self.last_seen or time.time())
        window = self._prune(now)
        elapsed = self._elapsed(now)
        return len(window) / elapsed if elapsed > 0 else 0.0

    def bytes_per_second(self, now: float | None = None) -> float:
        now = now if now is not None else (self.last_seen or time.time())
        window = self._prune(now)
        elapsed = self._elapsed(now)
        total = sum(length for _, length in window)
        return total / elapsed if elapsed > 0 else 0.0

    def duration(self) -> float:
        if self.started_at is None or self.last_seen is None:
            return 0.0
        return max(self.last_seen - self.started_at, 0.0)

    def snapshot(self, now: float | None = None) -> TrafficSnapshot:
        now = now if now is not None else (self.last_seen or time.time())
        return TrafficSnapshot(
            total_packets=self.total_packets,
            total_bytes=self.total_bytes,
            duration=self.duration(),
            packets_per_second=round(self.packets_per_second(now), 1),
            bytes_per_second=round(self.bytes_per_second(now), 1),
            avg_packet_size=round(self.total_bytes / self.total_packets) if self.total_packets else 0,
            unique_hosts=len(self._hosts),
            by_protocol=dict(self._by_protocol.most_common()),
            top_sources=self._by_source.most_common(TOP_N),
            top_destinations=self._by_destination.most_common(TOP_N),
            top_ports=self._by_port.most_common(TOP_N),
            active_alerts=self.alert_count,
        )

    def reset(self) -> None:
        """Clear counters, including the rolling windows."""
        self._window.clear()
        self._by_protocol.clear()
        self._by_source.clear()
        self._by_destination.clear()
        self._by_port.clear()
        self._hosts.clear()
        self.total_packets = 0
        self.total_bytes = 0
        self.started_at = None
        self.last_seen = None
        self.alert_count = 0

    def restore(self, records: list[PacketRecord]) -> None:
        """Rebuild counters from a loaded capture so stats survive save/load."""
        self.reset()
        self.observe_many(records)
