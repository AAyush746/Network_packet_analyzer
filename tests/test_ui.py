"""GUI tests.

These need a display, so they skip when Tk cannot open one (headless CI).
They still exercise real widget wiring: ingest, filtering, sorting, detail
rendering, alerts and export -- the parts that break silently when a variable
name or column order is wrong.
"""

import tkinter as tk

import pytest

pytest.importorskip("tkinter")

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw

from pktanalyzer.capture import replay
from pktanalyzer.ui.app import MAX_VISIBLE_ROWS, AnalyzerApp


@pytest.fixture(scope="module")
def root():
    try:
        window = tk.Tk()
    except tk.TclError as error:
        pytest.skip(f"no display available: {error}")
    window.withdraw()
    yield window
    window.destroy()


@pytest.fixture
def app(root):
    instance = AnalyzerApp(root)
    yield instance
    instance.clear()
    instance.shutdown()


@pytest.fixture
def traffic():
    frames = [
        Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51515, dport=443, flags="PA")
        / Raw(load=b"GET / HTTP/1.1\r\n\r\n"),
        Ether() / IP(src="10.0.0.3", dst="8.8.8.8") / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
        Ether() / IP(src="10.0.0.4", dst="10.0.0.5") / ICMP(),
        Ether() / ARP(psrc="10.0.0.4", pdst="10.0.0.254"),
    ]
    return replay(frames)


class TestConstruction:
    def test_widgets_are_built(self, app):
        assert app.tree.winfo_exists()
        assert app.alert_tree.winfo_exists()
        assert app.detail.winfo_exists()
        assert app.start_btn.winfo_exists()

    def test_columns_match_the_record_projection(self, app):
        from pktanalyzer.ui.app import COLUMNS

        assert tuple(app.tree["columns"]) == tuple(key for key, _, _ in COLUMNS)

    def test_start_button_is_enabled_and_stop_is_not(self, app):
        assert str(app.start_btn["state"]) == tk.NORMAL
        assert str(app.stop_btn["state"]) == tk.DISABLED

    def test_interfaces_are_populated(self, app):
        assert app.iface_box["values"]

    def test_status_starts_idle(self, app):
        assert "Idle" in app._status_var.get()


class TestIngest:
    def test_rows_appear_in_the_tree(self, app, traffic):
        app._ingest(traffic, [])
        assert len(app.tree.get_children()) == len(traffic)

    def test_protocol_filter_limits_rows(self, app, traffic):
        app._protocol_filter.set("TCP")
        app._ingest(traffic, [])
        protocols = {app.tree.item(i)["values"][2] for i in app.tree.get_children()}
        assert protocols == {"TCP"}

    def test_service_filter_also_matches(self, app, traffic):
        app._protocol_filter.set("HTTPS")
        app._ingest(traffic, [])
        assert len(app.tree.get_children()) >= 1

    def test_text_search_matches_payload_and_addresses(self, app, traffic):
        app._filter_var.set("8.8.8.8")
        app._ingest(traffic, [])
        assert len(app.tree.get_children()) == 1

    def test_search_with_no_match_shows_nothing(self, app, traffic):
        app._filter_var.set("zzzz-no-such-host")
        app._ingest(traffic, [])
        assert len(app.tree.get_children()) == 0

    def test_ingest_enables_export(self, app, traffic):
        app._ingest(traffic, [])
        assert str(app.export_btn["state"]) == tk.NORMAL

    def test_records_buffer_is_bounded(self, app, traffic):
        for _ in range(3):
            app._ingest(traffic, [])
        assert len(app.records) <= MAX_VISIBLE_ROWS

    def test_duplicate_packet_indices_do_not_crash(self, app, traffic):
        """Row ids are decoupled from packet indexes, so replay is safe."""
        app._ingest(traffic, [])
        app._ingest(traffic, [])
        assert len(app.tree.get_children()) == len(traffic) * 2

    def test_alerts_are_rendered_and_tagged(self, app, traffic):
        app._ingest(traffic, app.detector.inspect_many(traffic))
        assert len(app.alert_tree.get_children()) == len(app.alerts)


class TestDetailView:
    def test_detail_renders_layer_tree(self, app, traffic):
        app._ingest(traffic, [])
        app.tree.selection_set(app.tree.get_children()[0])
        app._on_select()

        text = app.detail.get("1.0", tk.END)
        assert "IP" in text
        assert "TCP" in text
        assert "10.0.0.1" in text

    def test_detail_shows_payload(self, app, traffic):
        app._ingest(traffic, [])
        app.tree.selection_set(app.tree.get_children()[0])
        app._on_select()
        assert "payload hex" in app.detail.get("1.0", tk.END)

    def test_selecting_nothing_does_not_crash(self, app):
        app.tree.selection_remove(*app.tree.selection())
        app._on_select()

    def test_detail_is_read_only(self, app, traffic):
        app._ingest(traffic, [])
        app.tree.selection_set(app.tree.get_children()[0])
        app._on_select()
        assert str(app.detail["state"]) == tk.DISABLED


class TestSorting:
    def test_sorting_reorders_rows(self, app, traffic):
        app._ingest(traffic, [])
        app._sort_by("protocol")
        first_run = [app.tree.item(i)["values"][2] for i in app.tree.get_children()]
        app._sort_by("protocol")
        second_run = [app.tree.item(i)["values"][2] for i in app.tree.get_children()]

        assert first_run == sorted(first_run)
        assert second_run == sorted(second_run, reverse=True)

    def test_numeric_sort_is_numeric_not_lexicographic(self, app):
        from pktanalyzer.models import PacketRecord

        records = [
            PacketRecord(index=i, timestamp=0.0, length=size, protocol="TCP", ttl=9)
            for i, size in enumerate([9, 100, 20])
        ]
        app._ingest(records, [])
        app._sort_by("length")

        lengths = [int(app.tree.item(i)["values"][9]) for i in app.tree.get_children()]
        assert lengths == [9, 20, 100]


class TestClearAndImport:
    def test_clear_empties_everything(self, app, traffic):
        app._ingest(traffic, app.detector.inspect_many(traffic))
        app.clear()

        assert len(app.tree.get_children()) == 0
        assert len(app.alert_tree.get_children()) == 0
        assert len(app.records) == 0
        assert app.stats.total_packets == 0
        assert app.detector.total_alerts == 0

    def test_clear_disables_export(self, app, traffic):
        app._ingest(traffic, [])
        app.clear()
        assert str(app.export_btn["state"]) == tk.DISABLED

    def test_import_rebuilds_stats_and_alerts(self, app, traffic, tmp_path):
        from pktanalyzer.export import save

        path = tmp_path / "cap.pcap"
        save(traffic, path)

        app.clear()
        from pktanalyzer.export import load

        records = load(path)
        app.stats.restore(records)
        for record in records:
            app.detector.inspect(record)
        app._ingest(records, app.detector.history)

        assert app.stats.total_packets == len(records)
        assert len(app.tree.get_children()) == len(records)


class TestStatsBar:
    def test_stats_labels_update_after_ingest(self, app, traffic):
        # _ingest is presentational only; counters are fed by the capture
        # thread, or by stats.restore() on the import path.
        app.stats.restore(traffic)
        app._ingest(traffic, [])
        app._refresh_stats()
        assert app.stat_labels["packets"].cget("text") == f"{len(traffic)}"

    @pytest.mark.parametrize("rate,expected", [
        (2_000_000_000, "2.0 GB/s"),
        (5_000_000, "5.0 MB/s"),
        (1_500, "1.5 KB/s"),
        (12, "12 B/s"),
    ])
    def test_bandwidth_is_human_readable(self, app, rate, expected):
        assert app._format_rate(rate) == expected

    def test_pump_is_scheduled(self, app):
        assert isinstance(app._pump_job, str)
