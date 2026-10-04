"""Tkinter user interface.

Kept deliberately thin. Every decision that matters -- decoding, statistics,
detection -- lives in the headless modules; this file only turns events into
widget calls. That split is what makes the project testable at all.

Threading: Tk may only be touched from the main thread. The capture engine
publishes to a queue and ``_pump`` drains it on an ``after`` timer, so no widget
is ever touched from the sniffer thread.
"""

from __future__ import annotations

import contextlib
import time
import tkinter as tk
from collections import deque
from tkinter import filedialog, messagebox, ttk

from ..capture import DRAIN_INTERVAL_MS, CaptureEngine, list_interfaces
from ..detect import DetectionEngine
from ..export import load, save
from ..models import Alert, PacketRecord
from ..stats import TrafficStats

COLUMNS = [
    ("index", "#", 60),
    ("timestamp", "Time", 90),
    ("protocol", "Protocol", 80),
    ("src_ip", "Source", 130),
    ("src_port", "Src Port", 70),
    ("dst_ip", "Destination", 130),
    ("dst_port", "Dst Port", 70),
    ("service", "Service", 90),
    ("ttl", "TTL", 50),
    ("length", "Len", 60),
    ("info", "Info", 320),
]

SEVERITY_COLOURS = {
    "high": "#ff6b6b",
    "medium": "#ffa94d",
    "low": "#ffd43b",
    "info": "#74c0fc",
}

# The table cannot grow without bound: a long capture would otherwise turn the
# UI into a memory leak. Oldest rows are evicted first.
MAX_VISIBLE_ROWS = 20_000
MAX_ALERT_ROWS = 2_000


class AnalyzerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("pktanalyzer")
        self.root.geometry("1280x820")
        self.root.minsize(900, 600)

        self.stats = TrafficStats()
        self.detector = DetectionEngine()
        self.engine: CaptureEngine | None = None

        # Row id -> record. The treeview only holds what fits in memory; this
        # ring buffer is the authority for exports and detail views.
        self.records: deque[PacketRecord] = deque(maxlen=MAX_VISIBLE_ROWS)
        self.alerts: deque[Alert] = deque(maxlen=MAX_ALERT_ROWS)
        self._alert_counts: dict[str, int] = {}
        self._pump_job: str | None = None

        # Row identity is deliberately decoupled from the packet index. Using
        # record.index as the tree item id breaks as soon as the same index
        # arrives twice (replay, or importing after a live capture) and Tk
        # raises "Item N already exists" inside the pump loop.
        self._row_seq = 0
        self._row_to_index: dict[str, int] = {}

        self._filter_var = tk.StringVar()
        self._bpf_var = tk.StringVar(value="")
        self._iface_var = tk.StringVar()
        self._status_var = tk.StringVar(value="Idle")
        self._protocol_filter = tk.StringVar(value="All")
        self._follow = tk.BooleanVar(value=True)

        self._build_style()
        self._build_widgets()
        self._refresh_interfaces()
        self._pump()

    # --- construction ---------------------------------------------------

    def _build_style(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Treeview", rowheight=22, font=("TkFixedFont", 10))
        style.configure("Treeview.Heading", font=("TkDefaultFont", 10, "bold"))
        style.configure("Stat.TLabel", font=("TkDefaultFont", 16, "bold"))
        style.configure("Hint.TLabel", foreground="#666")

        # A new ttk style needs a layout as well as configuration; without this
        # the widget fails at construction time with "Layout ... not found".
        style.layout("AlertTreeview", style.layout("Treeview"))
        style.configure("AlertTreeview", rowheight=22)

    def _build_widgets(self) -> None:
        self._build_toolbar()

        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        table_frame = ttk.Frame(paned)
        self._build_table(table_frame)
        paned.add(table_frame, weight=3)

        bottom = ttk.Frame(paned)
        bottom.columnconfigure(0, weight=3)
        bottom.columnconfigure(1, weight=2)
        self._build_detail(bottom)
        self._build_alerts(bottom)
        paned.add(bottom, weight=2)

        self._build_statusbar()

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(8, 8, 8, 4))
        bar.pack(fill=tk.X)

        ttk.Label(bar, text="Interface").pack(side=tk.LEFT)
        self.iface_box = ttk.Combobox(bar, textvariable=self._iface_var, width=18, state="readonly")
        self.iface_box.pack(side=tk.LEFT, padx=(4, 10))
        self.iface_box.bind("<<ComboboxSelected>>", lambda _e: None)

        ttk.Label(bar, text="BPF filter").pack(side=tk.LEFT)
        ttk.Entry(bar, textvariable=self._bpf_var, width=24).pack(side=tk.LEFT, padx=(4, 10))

        self.start_btn = ttk.Button(bar, text="Start", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=2)
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=(10, 2))

        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        ttk.Label(bar, text="Show").pack(side=tk.LEFT)
        ttk.Combobox(
            bar, textvariable=self._protocol_filter, width=9, state="readonly",
            values=["All", "TCP", "UDP", "ICMP", "ARP", "HTTPS", "HTTP", "DNS"],
        ).pack(side=tk.LEFT, padx=(4, 10))
        self._protocol_filter.trace_add("write", lambda *_: self._apply_filter())

        ttk.Label(bar, text="Search").pack(side=tk.LEFT)
        search = ttk.Entry(bar, textvariable=self._filter_var, width=20)
        search.pack(side=tk.LEFT, padx=(4, 4))
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())

        ttk.Checkbutton(bar, text="Follow", variable=self._follow).pack(side=tk.LEFT, padx=6)

        ttk.Button(bar, text="Import pcap", command=self.import_pcap).pack(side=tk.RIGHT, padx=2)
        self.export_btn = ttk.Button(bar, text="Export", command=self.export, state=tk.DISABLED)
        self.export_btn.pack(side=tk.RIGHT, padx=2)

    def _build_table(self, parent: ttk.Frame) -> None:
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            parent,
            columns=[key for key, _, _ in COLUMNS],
            show="headings",
            selectmode="browse",
        )
        for key, heading, width in COLUMNS:
            self.tree.heading(key, text=heading, command=lambda k=key: self._sort_by(k))
            self.tree.column(key, width=width, anchor=tk.W, stretch=(key == "info"))

        yscroll = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self._sort_key: str | None = None
        self._sort_reverse = False

    def _build_detail(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Packet detail", padding=6)
        frame.grid(row=0, column=0, sticky="nsew", padx=(0, 4))

        self.detail = tk.Text(frame, height=12, wrap=tk.NONE, font=("TkFixedFont", 10))
        self.detail.pack(fill=tk.BOTH, expand=True)
        self.detail.configure(state=tk.DISABLED)

        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.detail.yview)
        scroll.place(relx=1.0, rely=0, relheight=1.0, anchor="ne")
        self.detail.configure(yscrollcommand=scroll.set)

    def _build_alerts(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Alerts", padding=6)
        frame.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        self.alert_summary = ttk.Label(frame, text="0 alerts", style="Hint.TLabel")
        self.alert_summary.grid(row=0, column=0, sticky="w", pady=(0, 4))

        self.alert_tree = ttk.Treeview(
            frame, columns=("time", "severity", "rule", "message"),
            show="headings", selectmode="browse", style="AlertTreeview",
        )
        for key, heading, width in [
            ("time", "Time", 80), ("severity", "Severity", 80),
            ("rule", "Rule", 110), ("message", "Detail", 380),
        ]:
            self.alert_tree.heading(key, text=heading)
            self.alert_tree.column(key, width=width, anchor=tk.W)

        self.alert_tree.tag_configure("high", foreground=SEVERITY_COLOURS["high"])
        self.alert_tree.tag_configure("medium", foreground=SEVERITY_COLOURS["medium"])
        self.alert_tree.tag_configure("low", foreground=SEVERITY_COLOURS["low"])

        self.alert_tree.grid(row=1, column=0, sticky="nsew")
        ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.alert_tree.yview).grid(
            row=1, column=1, sticky="ns"
        )
        self.alert_tree.configure(yscrollcommand=self.alert_tree.yview)

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(8, 0, 8, 6))
        bar.pack(fill=tk.X)

        self.stat_labels: dict[str, ttk.Label] = {}
        for key in ("packets", "pps", "bandwidth", "hosts", "alerts"):
            ttk.Label(bar, text=key.capitalize()).pack(side=tk.LEFT, padx=(0, 4))
            label = ttk.Label(bar, text="-", style="Stat.TLabel")
            label.pack(side=tk.LEFT, padx=(0, 14))
            self.stat_labels[key] = label

        ttk.Label(bar, textvariable=self._status_var, style="Hint.TLabel").pack(side=tk.RIGHT)

    def _refresh_interfaces(self) -> None:
        interfaces = list_interfaces()
        self.iface_box["values"] = interfaces
        if interfaces and not self._iface_var.get():
            self._iface_var.set(interfaces[0])

    # --- capture control ------------------------------------------------

    def start_capture(self) -> None:
        if self.engine is not None and self.engine.is_running:
            return

        self.engine = CaptureEngine(
            iface=self._iface_var.get() or None,
            bpf=self._bpf_var.get().strip(),
            stats=self.stats,
            detector=self.detector,
        )
        try:
            self.engine.start()
        except ValueError as error:
            # Invalid BPF filter: report it instead of silently doing nothing.
            messagebox.showerror("Invalid filter", str(error))
            self._status_var.set("Filter rejected")
            self.engine = None
            return

        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self._status_var.set(f"Capturing on {self._iface_var.get()}")

    def stop_capture(self) -> None:
        if self.engine is not None:
            self.engine.stop()
            errors = list(self.engine.capture_stats.errors)
            if errors:
                # The sniffer died (usually permissions). Say so rather than
                # leaving a dead UI looking like it is still capturing.
                messagebox.showerror("Capture stopped", errors[0])
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self._status_var.set("Stopped")
        self._refresh_stats()

    def clear(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)
        self.records.clear()
        self.alerts.clear()
        self._alert_counts.clear()
        self._row_to_index.clear()
        self.stats.reset()
        self.detector.reset()
        self.export_btn.configure(state=tk.DISABLED)
        self._set_detail("")
        self._refresh_stats()
        self._status_var.set("Cleared")

    # --- the pump: main thread drains the capture queue -----------------

    def _pump(self) -> None:
        if self.engine is not None:
            records, alerts = self.engine.drain()
            if records:
                self._ingest(records, alerts)
            if self.engine.is_running is False and self.engine.capture_stats.errors:
                self.stop_capture()
        self._refresh_stats()
        # Keep the job id so a test (or shutdown path) can cancel the timer;
        # otherwise it reschedules forever against a destroyed root.
        self._pump_job = self.root.after(DRAIN_INTERVAL_MS, self._pump)

    def shutdown(self) -> None:
        """Stop capturing and cancel timers. Safe to call more than once."""
        if getattr(self, "_pump_job", None):
            with contextlib.suppress(tk.TclError):
                self.root.after_cancel(self._pump_job)
            self._pump_job = None
        if self.engine is not None:
            self.engine.stop()
            self.engine = None

    def _ingest(self, records: list[PacketRecord], alerts: list[Alert]) -> None:
        """Insert a batch. Runs only on the main thread."""
        wanted = self._protocol_filter.get()
        needle = self._filter_var.get().strip().lower()

        for record in records:
            self.records.append(record)

            if wanted != "All" and record.protocol != wanted and record.service != wanted:
                continue
            if needle and needle not in self._detail_text(record).lower():
                continue

            self._insert_row(record)

        for alert in alerts:
            self._insert_alert(alert)

        if records:
            self.export_btn.configure(state=tk.NORMAL)
        if self._follow.get() and records:
            children = self.tree.get_children()
            if children:
                self.tree.see(children[-1])

        self._maybe_evict()

    def _insert_row(self, record: PacketRecord) -> str:
        """Add one row and return its item id."""
        iid = str(self._row_seq)
        self._row_seq += 1
        self._row_to_index[iid] = record.index
        self.tree.insert("", tk.END, iid=iid, values=record.table_row())
        return iid

    def _insert_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)
        self._alert_counts[alert.rule] = self._alert_counts.get(alert.rule, 0) + 1
        self.alert_tree.insert(
            "", tk.END,
            values=(
                time.strftime("%H:%M:%S", time.localtime(alert.timestamp)),
                alert.severity, alert.rule, alert.message,
            ),
            tags=(alert.severity,),
        )
        summary = ", ".join(f"{rule}x{count}" for rule, count in self._alert_counts.items())
        self.alert_summary.configure(text=summary or "0 alerts")

    def _maybe_evict(self) -> None:
        """Trim the treeview to MAX_VISIBLE_ROWS, oldest first."""
        excess = len(self.tree.get_children()) - MAX_VISIBLE_ROWS
        if excess <= 0:
            return
        for item in self.tree.get_children()[:excess]:
            self.tree.delete(item)

    def _refresh_stats(self) -> None:
        snapshot = self.stats.snapshot()
        self.stat_labels["packets"].configure(text=f"{snapshot.total_packets:,}")
        self.stat_labels["pps"].configure(text=f"{snapshot.packets_per_second:,.0f}/s")
        self.stat_labels["bandwidth"].configure(text=self._format_rate(snapshot.bytes_per_second))
        self.stat_labels["hosts"].configure(text=f"{snapshot.unique_hosts}")
        self.stat_labels["alerts"].configure(text=f"{self.detector.total_alerts}")

    @staticmethod
    def _format_rate(bytes_per_second: float) -> str:
        for unit, scale in (("GB/s", 1e9), ("MB/s", 1e6), ("KB/s", 1e3)):
            if bytes_per_second >= scale:
                return f"{bytes_per_second / scale:.1f} {unit}"
        return f"{bytes_per_second:.0f} B/s"

    # --- filtering and sorting -----------------------------------------

    def _matches(self, record: PacketRecord) -> bool:
        wanted = self._protocol_filter.get()
        if wanted != "All" and record.protocol != wanted and record.service != wanted:
            return False
        needle = self._filter_var.get().strip().lower()
        return not needle or needle in self._detail_text(record).lower()

    def _apply_filter(self) -> None:
        """Rebuild the visible rows from the in-memory records."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        needle = self._filter_var.get().strip().lower()
        wanted = self._protocol_filter.get()

        for record in self.records:
            if wanted != "All" and record.protocol != wanted and record.service != wanted:
                continue
            if needle and needle not in self._detail_text(record).lower():
                continue
            self._insert_row(record)

    def _sort_by(self, key: str) -> None:
        """Sort the visible rows by a column."""
        index = [c[0] for c in COLUMNS].index(key)
        self._sort_reverse = not self._sort_reverse if self._sort_key == key else False
        self._sort_key = key
        rows = [(self.tree.item(i)["values"], i) for i in self.tree.get_children()]

        def sort_key(pair):
            value = pair[0][index]
            try:
                return (0, float(value))
            except (TypeError, ValueError):
                return (1, str(value).lower())

        rows.sort(key=sort_key, reverse=self._sort_reverse)
        for position, (_, item) in enumerate(rows):
            self.tree.move(item, "", position)

    # --- detail view ----------------------------------------------------

    def _on_select(self, _event: object = None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        index = self._row_to_index.get(selection[0])
        if index is None:
            return
        for record in self.records:
            if record.index == index:
                self._set_detail(self._detail_text(record))
                break

    def _set_detail(self, text: str) -> None:
        self.detail.configure(state=tk.NORMAL)
        self.detail.delete("1.0", tk.END)
        self.detail.insert("1.0", text)
        self.detail.configure(state=tk.DISABLED)

    @staticmethod
    def _detail_text(record: PacketRecord) -> str:
        lines = [
            f"#{record.index}  {record.length} bytes  service={record.service or '-'}",
            f"src  {record.src_mac or '-'}  ({record.src_ip or '-'}"
            f"{':' + str(record.src_port) if record.src_port else ''})",
            f"dst  {record.dst_mac or '-'}  ({record.dst_ip or '-'}"
            f"{':' + str(record.dst_port) if record.dst_port else ''})",
            "",
        ]
        lines += [f"  {layer.summary()}" for layer in record.layers]
        if record.payload_hex:
            lines += ["", f"payload hex   : {record.payload_hex}",
                      f"payload ascii : {record.payload_ascii}"]
        return "\n".join(lines)

    def shutdown_and_quit(self) -> None:
        """Window close handler: stop the capture thread before tearing down Tk.

        Without this the process can exit with a live sniffer holding a raw
        socket, which shows up as a 'device busy' error on the next run.
        """
        self.shutdown()
        self.root.quit()

    # --- import / export ------------------------------------------------

    def import_pcap(self) -> None:
        path = filedialog.askopenfilename(
            title="Import pcap", filetypes=[("pcap files", "*.pcap *.cap"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            # keep_raw so the user can re-export what they just imported.
            records = load(path, keep_raw=True)
        except Exception as error:
            messagebox.showerror("Import failed", str(error))
            return

        self.clear()
        self.stats.restore(records)
        for record in records:
            self.detector.inspect(record)
        self._ingest(records, self.detector.history)
        self.export_btn.configure(state=tk.NORMAL)
        self._refresh_stats()
        self._status_var.set(f"Loaded {len(records):,} packets from {path.rsplit('/', 1)[-1]}")

    def export(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export capture",
            defaultextension=".pcap",
            filetypes=[("pcap", "*.pcap"), ("CSV", "*.csv"), ("JSON", "*.json")],
        )
        if not path:
            return
        try:
            written = save(self.records, path)
        except Exception as error:
            messagebox.showerror("Export failed", str(error))
            return
        if written == 0:
            messagebox.showwarning("Nothing written", "No packets available to export.")
            return
        self._status_var.set(f"Exported {written:,} packets")


def main() -> None:
    root = tk.Tk()
    app = AnalyzerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.shutdown_and_quit)
    root.mainloop()


if __name__ == "__main__":
    main()
