"""Capture engine tests.

These mock ``sniff`` instead of opening a raw socket on purpose: CI runners do
not have CAP_NET_RAW, so a test suite that requires root would simply never run.
The threading contract, queue behaviour and error paths are all still exercised.
"""

import threading
import time

import pytest
from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw

from pktanalyzer import capture
from pktanalyzer.capture import CaptureEngine, list_interfaces, replay, validate_bpf
from pktanalyzer.detect import DetectionEngine, PortScanDetector
from pktanalyzer.models import Alert, PacketRecord
from pktanalyzer.stats import TrafficStats

ETH = dict(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")


def syn(dport=80, flags="S", dst="10.0.0.2"):
    return Ether(**ETH) / IP(src="10.0.0.1", dst=dst) / TCP(dport=dport, flags=flags)


def sweep(ports=11, hosts=11, src="10.0.0.1"):
    """A horizontal scan: distinct ports spread across distinct hosts.

    The port-scan rule requires breadth on both axes, so a single-host sweep
    no longer produces alerts and cannot be used to assert alert plumbing.
    """
    return [syn(dport=1000 + i, dst=f"10.9.{i % hosts}.{i % hosts + 1}") for i in range(ports)]


@pytest.fixture
def fake_sniff(monkeypatch):
    """Replace scapy's sniff with a deterministic stand-in.

    ``state["finished"]`` lets a test wait until the worker has actually fed
    every packet before calling ``stop()``. Without that handshake the test
    races: the real ``stop_filter`` contract means a stop issued immediately
    after ``start()`` legitimately truncates the feed, which is correct
    behaviour but makes for a flaky assertion.
    """
    state = {
        "packets": [],
        "kwargs": {},
        "finished": threading.Event(),
        "block": False,
        "release": threading.Event(),
    }

    def _sniff(prn=None, **kwargs):
        state["kwargs"] = kwargs
        stop_filter = kwargs.get("stop_filter")
        if state["block"]:
            state["release"].wait(5)
        for packet in state["packets"]:
            if state["block"] and state["release"].is_set():
                break
            if stop_filter and stop_filter(packet):
                break
            if prn:
                prn(packet)
        state["finished"].set()

    monkeypatch.setattr(capture, "sniff", _sniff)

    def run_capture(engine, packets=None, wait=True):
        """Start, wait for the feed to finish, then stop. Returns the engine."""
        if packets is not None:
            state["packets"] = packets
        state["finished"] = threading.Event()
        engine.start()
        if wait:
            assert state["finished"].wait(5), "capture thread did not finish"
        engine.stop()
        return engine

    state["run"] = run_capture
    return state


class TestInterfaceDiscovery:
    def test_returns_a_non_empty_list(self):
        assert isinstance(list_interfaces(), list)
        assert list_interfaces()

    def test_never_raises_when_enumeration_blows_up(self, monkeypatch):
        class Exploding:
            @property
            def ifaces(self):
                raise RuntimeError("netlink unavailable")

        monkeypatch.setattr(capture.scapy.config, "conf", Exploding())
        assert list_interfaces() == ["lo"]

    def test_falls_back_to_loopback_when_empty(self, monkeypatch):
        monkeypatch.setattr(capture.scapy.config.conf, "ifaces", {})
        assert list_interfaces() == ["lo"]

    def test_interfaces_without_addresses_are_filtered(self, monkeypatch):
        class Iface:
            def __init__(self, ip, mac):
                self.ip, self.mac = ip, mac

        monkeypatch.setattr(
            capture.scapy.config.conf, "ifaces",
            {"eth0": Iface("10.0.0.5", "aa:bb:cc:dd:ee:ff"), "ghost": Iface(None, None)},
        )
        assert list_interfaces() == ["eth0"]


class TestBpfValidation:
    def test_empty_filter_is_allowed(self):
        assert validate_bpf("") == ""
        assert validate_bpf("   ") == ""

    def test_valid_filter_passes_through(self):
        assert validate_bpf("tcp port 443") == "tcp port 443"

    @pytest.mark.parametrize("bad", ["tcp portt", "not a filter!!", "src 999.999.999.999"])
    def test_invalid_filters_are_rejected(self, bad):
        with pytest.raises(ValueError):
            validate_bpf(bad)

    def test_start_rejects_invalid_filter_before_spawning(self, fake_sniff):
        engine = CaptureEngine(bpf="totally bogus ((((")
        with pytest.raises(ValueError):
            engine.start()
        assert not engine.is_running


class TestLifecycle:
    def test_start_and_stop_run_cleanly(self, fake_sniff):
        engine = fake_sniff["run"](CaptureEngine(), [syn()] * 10)

        assert not engine.is_running
        assert len(engine.drain()[0]) == 10

    def test_start_is_idempotent_while_running(self, fake_sniff):
        fake_sniff["block"] = True
        engine = CaptureEngine()
        engine.start()
        try:
            first = engine._thread
            engine.start()
            assert engine._thread is first
        finally:
            fake_sniff["release"].set()
            engine.stop()

    def test_stop_is_safe_when_never_started(self):
        CaptureEngine().stop()

    def test_context_manager_captures_and_stops(self, fake_sniff):
        fake_sniff["block"] = True
        fake_sniff["packets"] = [syn()] * 5
        with CaptureEngine() as engine:
            assert engine.is_running
        assert not engine.is_running

    def test_capture_failure_is_recorded_not_raised(self, monkeypatch):
        def boom(**kwargs):
            raise PermissionError(1, "Operation not permitted")

        monkeypatch.setattr(capture, "sniff", boom)
        engine = CaptureEngine()
        engine.start()
        engine.stop()

        assert engine.capture_stats.errors
        assert "permission" in engine.capture_stats.errors[0].lower()

    def test_unexpected_error_is_recorded_not_raised(self, monkeypatch):
        def boom(**kwargs):
            raise KeyboardInterrupt if False else ValueError("weird")

        monkeypatch.setattr(capture, "sniff", boom)
        engine = CaptureEngine()
        engine.start()
        engine.stop()

        assert "unexpected capture error" in engine.capture_stats.errors[0]

    def test_stop_filter_is_passed_through(self, fake_sniff):
        fake_sniff["run"](CaptureEngine(), [syn()])
        assert callable(fake_sniff["kwargs"].get("stop_filter"))


class TestQueueDrain:
    def test_drain_returns_records_and_alerts(self, fake_sniff):
        detector = DetectionEngine(rules=[PortScanDetector(threshold=5, cooldown=0.0)])
        packets = sweep()
        engine = fake_sniff["run"](CaptureEngine(detector=detector), packets)

        records, alerts = engine.drain()

        assert len(records) == 11
        assert all(isinstance(r, PacketRecord) for r in records)
        assert any(isinstance(a, Alert) for a in alerts)

    def test_drain_respects_batch_limit(self, fake_sniff):
        engine = fake_sniff["run"](CaptureEngine(), [syn()] * 300)

        assert len(engine.drain(max_items=50)[0]) == 50

    def test_drain_returns_flat_alert_objects_not_bundles(self, fake_sniff):
        """Each queued item carries an alert tuple; drain must flatten it."""
        packets = sweep()
        engine = fake_sniff["run"](
            CaptureEngine(detector=DetectionEngine(rules=[PortScanDetector(threshold=5)])),
            packets,
        )

        records, alerts = engine.drain()

        assert alerts, "expected alerts"
        assert all(isinstance(alert, Alert) for alert in alerts)

    def test_drain_on_empty_queue_returns_nothing(self):
        records, alerts = CaptureEngine().drain()
        assert records == [] and alerts == []

    def test_drain_does_not_block(self):
        engine = CaptureEngine()
        started = time.monotonic()
        engine.drain()
        assert time.monotonic() - started < 0.1

    def test_indices_are_sequential(self, fake_sniff):
        engine = fake_sniff["run"](CaptureEngine(), [syn() for _ in range(20)])

        indices = [r.index for r in engine.drain()[0]]
        assert indices == list(range(20))

    def test_queue_overflow_is_counted_not_fatal(self, fake_sniff):
        engine = fake_sniff["run"](CaptureEngine(queue_size=10), [syn() for _ in range(200)])

        assert engine.capture_stats.packets_dropped > 0
        assert engine.capture_stats.loss_ratio > 0
        assert len(engine.drain(max_items=999)[0]) == 10


class TestAnalyzerIntegration:
    def test_stats_are_fed_from_the_capture_thread(self, fake_sniff):
        stats = TrafficStats()
        engine = fake_sniff["run"](CaptureEngine(stats=stats), [syn(dport=443) for _ in range(30)])
        engine.drain()

        assert stats.total_packets == 30
        assert stats.snapshot().by_protocol == {"TCP": 30}

    def test_alerts_are_counted_on_stats(self, fake_sniff):
        stats, detector = TrafficStats(), DetectionEngine(rules=[PortScanDetector(threshold=5)])
        packets = sweep()
        engine = fake_sniff["run"](CaptureEngine(stats=stats, detector=detector), packets)
        engine.drain()

        assert detector.total_alerts > 0
        assert stats.alert_count == detector.total_alerts

    def test_mixed_protocols_all_survive_the_pipeline(self, fake_sniff):
        stats = TrafficStats()
        packets = [syn(), Ether(**ETH) / IP() / UDP(dport=53), Ether(**ETH) / IP() / ICMP()]
        engine = fake_sniff["run"](CaptureEngine(stats=stats), packets)

        records, _ = engine.drain()
        assert {r.protocol for r in records} == {"TCP", "UDP", "ICMP"}


class TestRobustness:
    def test_malformed_frame_does_not_kill_the_thread(self, fake_sniff):
        class Exploding:
            def __getattr__(self, name):
                raise RuntimeError("frame is broken")

        engine = fake_sniff["run"](CaptureEngine(), [Exploding(), syn(), syn()])

        records, _ = engine.drain()
        assert len(records) == 2
        assert engine.capture_stats.decode_failures == 1

    def test_analyzer_failure_does_not_stop_ingestion(self, fake_sniff):
        class BadDetector:
            def inspect(self, record):
                raise RuntimeError("rule exploded")

        engine = fake_sniff["run"](CaptureEngine(detector=BadDetector()), [syn() for _ in range(10)])

        records, _ = engine.drain()
        assert len(records) == 10, "a broken rule must not discard decoded packets"
        assert engine.detector_failures == 10
        assert engine.capture_stats.decode_failures == 0

    def test_capture_thread_is_a_daemon(self, fake_sniff):
        fake_sniff["block"] = True
        engine = CaptureEngine()
        engine.start()
        try:
            assert engine._thread.daemon
        finally:
            fake_sniff["release"].set()
            engine.stop()

    def test_concurrent_start_stop_cycles(self, fake_sniff):
        engine = CaptureEngine()

        for _ in range(15):
            fake_sniff["run"](engine, [syn() for _ in range(5)])

        assert not engine.is_running


class TestReplay:
    def test_replay_decodes_without_sniffing(self):
        packets = [syn(dport=80), Ether(**ETH) / IP() / UDP(dport=53)]
        records = replay(packets)

        assert len(records) == 2
        assert records[0].protocol == "TCP"
        assert records[1].protocol == "UDP"

    def test_replay_assigns_indices(self):
        records = replay([syn() for _ in range(5)])
        assert [r.index for r in records] == [0, 1, 2, 3, 4]

    def test_replay_survives_unsettable_time(self):
        records = replay([Raw(b"abc")])
        assert records[0].timestamp > 0


class TestThreadSafety:
    def test_packets_produced_from_a_thread_are_safe_to_drain(self, fake_sniff):
        """Mirrors the real UI loop: produce on a worker, drain on the main thread."""
        engine = fake_sniff["run"](
            CaptureEngine(stats=TrafficStats(), detector=DetectionEngine()),
            [syn() for _ in range(100)],
        )

        total, guard = 0, threading.Lock()
        while True:
            batch, _ = engine.drain(max_items=7)
            if not batch:
                break
            with guard:
                total += len(batch)

        assert total == 100
