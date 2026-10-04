"""Detection tests.

The accuracy test at the bottom is the important one: it synthesises labelled
normal and malicious traffic and scores the rule, so the precision/recall figure
quoted in the README is reproducible rather than invented.
"""

import pytest
from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw

from pktanalyzer.decode import decode
from pktanalyzer.detect import (
    DetectionEngine,
    LargeTransferDetector,
    PlaintextCredentialDetector,
    PortScanDetector,
    SynFloodDetector,
    measure_accuracy,
)

ETH = dict(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")


def record_of(packet, index=0, timestamp=1000.0):
    packet.time = timestamp
    return decode(packet, index)


def syn(src="10.0.0.1", dst="10.0.0.2", dport=80, flags="S"):
    return Ether(**ETH) / IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags=flags)


def horizontal(src="10.0.0.1", ports=20, hosts=20, start=1000.0, step=0.01):
    """A realistic horizontal scan: many ports spread across many hosts.

    Separate from ``syn`` so tests cannot accidentally model a single-host
    vertical sweep, which the rule deliberately ignores.
    """
    records = []
    for i in range(ports):
        records.append(
            record_of(
                syn(src=src, dst=f"10.9.{i % hosts}.{i % hosts + 1}", dport=1000 + i),
                timestamp=start + i * step,
            )
        )
    return records


def vertical(src="10.0.0.1", ports=30, dst="10.0.0.2", start=1000.0, step=0.01):
    """One host opening many ports on a single destination."""
    return [
        record_of(syn(src=src, dst=dst, dport=1000 + i), timestamp=start + i * step)
        for i in range(ports)
    ]


class TestPortScan:
    def test_broad_sweep_is_flagged(self):
        detector = PortScanDetector(threshold=10, window=5.0)

        alerts = [detector.inspect(r) for r in horizontal(ports=20, hosts=20)]

        raised = [a for a in alerts if a]
        assert len(raised) == 1
        assert raised[0].rule == "port_scan"
        assert "10.0.0.1" in raised[0].message

    def test_sweep_message_reports_both_axes(self):
        """An operator needs to see breadth, not just a bare rule name."""
        detector = PortScanDetector(threshold=10, window=5.0)

        raised = [a for a in (detector.inspect(r) for r in horizontal(ports=20, hosts=20)) if a]

        # Fires as soon as both axes cross the threshold, so the reported
        # breadth is the threshold, not the eventual total.
        assert "10 distinct ports" in raised[0].message
        assert "10 hosts" in raised[0].message

    def test_vertical_sweep_on_one_host_is_ignored_by_default(self):
        """The false positive that made precision collapse to 0.500.

        Service discovery, P2P clients and monitoring agents all open many ports
        on a single destination. Counting ports alone cannot tell them apart
        from a scanner; requiring breadth across hosts can.
        """
        detector = PortScanDetector(threshold=10, window=5.0)

        alerts = [detector.inspect(r) for r in vertical(ports=30)]

        assert [a for a in alerts if a] == []

    def test_vertical_sweep_is_detectable_when_explicitly_requested(self):
        """Single-host sweeps are real; the gate is opt-out, not opt-in."""
        detector = PortScanDetector(threshold=10, window=5.0, min_destinations=1)

        alerts = [detector.inspect(r) for r in vertical(ports=30)]

        assert [a for a in alerts if a]

    def test_wide_ports_narrow_hosts_is_not_a_scan(self):
        """Both axes must be wide. Many ports on two hosts is not a sweep."""
        detector = PortScanDetector(threshold=10, window=5.0)

        alerts = [
            detector.inspect(r)
            for r in horizontal(ports=30, hosts=2)
        ]

        assert [a for a in alerts if a] == []

    def test_narrow_ports_wide_hosts_is_not_a_scan(self):
        """Many hosts but few ports each is normal internet traffic."""
        detector = PortScanDetector(threshold=10, window=5.0)

        alerts = [
            detector.inspect(r)
            for r in horizontal(ports=4, hosts=30)
        ]

        assert [a for a in alerts if a] == []

    def test_ordinary_browsing_is_not_flagged(self):
        """Six ports to different hosts is a browser, not a scanner."""
        detector = PortScanDetector(threshold=10, window=5.0)

        for i, port in enumerate([80, 443, 53, 22]):
            for host in ["10.0.0.3", "10.0.0.4", "10.0.0.5"]:
                detector.inspect(record_of(syn(dst=host, dport=port), timestamp=1000.0 + i * 0.01))

        assert detector.inspect(record_of(syn(dport=443), timestamp=1001.0)) is None

    def test_repeated_single_port_is_not_a_scan(self):
        """Volume alone must not trigger; only distinct destinations count."""
        detector = PortScanDetector(threshold=10, window=5.0)

        for i in range(200):
            detector.inspect(record_of(syn(dport=443), timestamp=1000.0 + i * 0.001))

        assert detector.inspect(record_of(syn(dport=443), timestamp=1001.0)) is None

    def test_slow_scan_falls_outside_the_window(self):
        """Same port count, spread over 30s, is below the rate threshold."""
        detector = PortScanDetector(threshold=10, window=5.0)

        for r in horizontal(ports=20, hosts=20, start=1000.0, step=1.0):
            detector.inspect(r)

        assert detector.inspect(
            record_of(syn(dst="10.9.99.99", dport=9999), timestamp=1030.0)
        ) is None

    def test_cooldown_suppresses_repeat_alerts(self):
        detector = PortScanDetector(threshold=5, window=10.0, cooldown=30.0)

        first = None
        for r in horizontal(ports=29, hosts=29, start=1000.0, step=0.05):
            first = first or detector.inspect(r)

        second = detector.inspect(
            record_of(syn(dst="10.9.88.88", dport=9999), timestamp=1002.0)
        )

        assert first is not None
        assert second is None

    def test_two_scanners_are_reported_separately(self):
        detector = PortScanDetector(threshold=8, window=10.0)

        first = second = None
        for r in horizontal(src="10.1.1.1", ports=14, hosts=14):
            first = first or detector.inspect(r)
        for r in horizontal(src="10.2.2.2", ports=14, hosts=14):
            second = second or detector.inspect(r)

        assert first is not None and second is not None
        assert "10.1.1.1" in first.message
        assert "10.2.2.2" in second.message

    def test_packets_without_ports_are_ignored(self):
        detector = PortScanDetector(threshold=2)
        alert = detector.inspect(record_of(Ether(**ETH) / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()))
        assert alert is None

    def test_missing_addresses_are_ignored(self):
        detector = PortScanDetector(threshold=1)
        record = record_of(Ether(**ETH) / IP() / TCP(dport=80))
        record.src_ip = ""
        assert detector.inspect(record) is None


class TestSynFlood:
    def test_unanswered_syn_burst_is_flagged(self):
        detector = SynFloodDetector(threshold=50, window=5.0)

        alert = None
        for i in range(60):
            alert = alert or detector.inspect(record_of(syn(), timestamp=1000.0 + i * 0.01))

        assert alert is not None
        assert alert.rule == "syn_flood"
        assert "unacknowledged" in alert.message

    def test_acknowledged_traffic_is_not_flagged(self):
        """The whole point: a busy but well-behaved client must stay silent."""
        detector = SynFloodDetector(threshold=20, window=5.0)

        for i in range(100):
            detector.inspect(record_of(syn(), timestamp=1000.0 + i * 0.01))
            detector.inspect(record_of(syn(flags="SA"), timestamp=1000.0 + i * 0.01))

        assert detector.inspect(record_of(syn(), timestamp=1001.0)) is None

    def test_reset_clears_outstanding_state(self):
        detector = SynFloodDetector(threshold=30, window=10.0)
        for i in range(29):
            detector.inspect(record_of(syn(), timestamp=1000.0 + i * 0.01))

        detector.inspect(record_of(syn(flags="R"), timestamp=1000.5))
        alert = detector.inspect(record_of(syn(), timestamp=1000.6))

        assert alert is None

    def test_udp_traffic_is_ignored(self):
        detector = SynFloodDetector(threshold=1)
        packet = Ether(**ETH) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=53)
        assert detector.inspect(record_of(packet)) is None


class TestPlaintextCredentials:
    def test_http_authorization_header_is_flagged(self):
        detector = PlaintextCredentialDetector()
        body = Raw(load=b"GET /admin HTTP/1.1\r\nHost: x\r\n"
                           b"Authorization: Basic YWRtaW46c2VjcmV0\r\n\r\n")
        record = record_of(Ether(**ETH) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80) / body)

        alert = detector.inspect(record)
        assert alert is not None
        assert alert.rule == "plaintext_credentials"

    def test_secret_is_never_included_in_the_alert(self):
        """An analyzer must not copy credentials into its own log."""
        detector = PlaintextCredentialDetector()
        body = Raw(load=b"POST /login HTTP/1.1\r\npassword=hunter2secret\r\n\r\n")
        record = record_of(Ether(**ETH) / IP() / TCP(dport=80) / body)

        alert = detector.inspect(record)

        assert alert is not None
        assert "hunter2secret" not in alert.message

    def test_ftp_password_is_flagged(self):
        detector = PlaintextCredentialDetector()
        record = record_of(Ether(**ETH) / IP() / TCP(dport=21) / Raw(load=b"PASS s3cr3t\r\n"))

        assert detector.inspect(record) is not None

    def test_encrypted_traffic_is_not_inspected(self):
        """Scanning TLS bytes would match by coincidence and cost false positives."""
        detector = PlaintextCredentialDetector()
        blob = b"GET / HTTP/1.1\r\nAuthorization: Basic abc\r\n"
        record = record_of(Ether(**ETH) / IP() / TCP(dport=443) / Raw(load=blob))

        assert detector.inspect(record) is None

    def test_ordinary_http_is_not_flagged(self):
        detector = PlaintextCredentialDetector()
        body = Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        record = record_of(Ether(**ETH) / IP() / TCP(dport=80) / body)

        assert detector.inspect(record) is None

    def test_cooldown_limits_repeat_alerts(self):
        detector = PlaintextCredentialDetector(cooldown=60.0)
        body = Raw(load=b"Authorization: Basic abc\r\n")
        packet = Ether(**ETH) / IP() / TCP(dport=80) / body

        first = detector.inspect(record_of(packet, timestamp=1000.0))
        second = detector.inspect(record_of(packet, timestamp=1001.0))

        assert first is not None
        assert second is None


class TestLargeTransfer:
    def test_flow_crossing_threshold_is_flagged_once(self):
        detector = LargeTransferDetector(threshold_bytes=5_000)
        packet = Ether(**ETH) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=443) / Raw(load=b"x" * 100)

        alerts = [detector.inspect(record_of(packet, timestamp=1000.0 + i * 0.01)) for i in range(100)]
        raised = [a for a in alerts if a]

        assert len(raised) == 1
        assert raised[0].rule == "large_transfer"

    def test_small_flow_is_silent(self):
        detector = LargeTransferDetector(threshold_bytes=1_000_000)
        record = record_of(Ether(**ETH) / IP() / TCP(dport=80))
        assert detector.inspect(record) is None


class TestEngine:
    def test_engine_runs_every_rule(self):
        engine = DetectionEngine()
        assert len(engine.rules) == 4

    def test_history_is_bounded(self):
        engine = DetectionEngine(rules=[PortScanDetector(threshold=1, cooldown=0.0)])
        for i in range(1200):
            engine.inspect(horizontal(ports=60, hosts=60, start=1000.0 + i * 0.01)[i % 60])

        assert len(engine.history) <= 500

    def test_a_broken_rule_does_not_stop_the_others(self):
        class Exploding:
            def inspect(self, record):
                raise RuntimeError("rule is broken")

        engine = DetectionEngine(rules=[Exploding(), PortScanDetector(threshold=5)])
        alerts = [engine.inspect(r) for r in horizontal(ports=11, hosts=11)]

        assert any(a for a in alerts)

    def test_reset_clears_history_and_rule_state(self):
        engine = DetectionEngine(rules=[PortScanDetector(threshold=2)])
        for r in horizontal(ports=7, hosts=7):
            engine.inspect(r)

        engine.reset()
        assert engine.history == []
        assert engine.total_alerts == 0

    def test_inspect_many_matches_per_packet_calls(self):
        engine = DetectionEngine()

        assert len(engine.inspect_many(horizontal(ports=20, hosts=20))) >= 1


class TestAccuracyMeasurement:
    """Reproducible precision/recall for the port-scan rule."""

    @staticmethod
    def build_traffic():
        positives, negatives = [], []

        for i in range(200):
            host = f"10.0.{i % 4}.{i % 9 + 1}"
            # Attack: one source sweeping ports on a single target.
            positives.append(record_of(syn(src="10.0.0.66", dst=host, dport=i % 400 + 1),
                                       timestamp=1000.0 + i * 0.02))
            # Benign: a handful of well-known ports spread across many hosts.
            negatives.append(record_of(syn(src=f"10.1.{i % 250}.5",
                                           dst=f"10.2.{i % 9}.{i % 250 + 1}",
                                           dport=[80, 443, 22, 53][i % 4]),
                                       timestamp=1000.0 + i * 0.02))

        return positives, negatives

    def test_port_scan_rule_scores_well_on_labelled_traffic(self):
        positives, negatives = self.build_traffic()
        report = measure_accuracy(positives, negatives)

        assert report["recall"] > 0.9, report
        assert report["precision"] > 0.9, report
        assert report["f1"] > 0.9, report

    def test_accuracy_report_separates_warmup_misses_from_real_errors(self):
        """A detector cannot fire before it has evidence.

        The first `threshold - 1` packets are spent filling the observation
        window before the rule can fire, so they are unavoidable misses rather
        than detection errors. That caps recall at 1 - (threshold-1)/n, and the
        ceiling should be asserted rather than an impossible zero false negatives.
        """
        positives, negatives = self.build_traffic()
        report = measure_accuracy(positives, negatives)

        warmup = PortScanDetector().threshold - 1

        assert report["false_positives"] == 0, "benign traffic must never be flagged"
        assert report["false_negatives"] == warmup
        assert report["recall"] == pytest.approx(1 - warmup / len(positives), abs=0.01)

    def test_single_host_sweep_is_not_a_false_positive(self):
        """Guards the defect that made precision collapse to 0.500.

        One host opening many ports on one destination is how service discovery,
        P2P clients and monitoring agents behave. The original rule counted
        distinct ports without counting distinct destinations, scored that
        benign traffic as a scan, and produced 286 false positives here.
        """
        report = measure_accuracy(
            horizontal(ports=300, hosts=36), vertical(ports=300, src="10.1.1.1")
        )

        assert report["false_positives"] == 0, report
        assert report["precision"] == 1.0, report

    def test_ambiguous_multi_host_sweep_is_a_known_false_positive(self):
        """Pins the residual limitation instead of hiding it.

        A host sweeping 300 ports across 20 hosts is indistinguishable from a
        small horizontal scan using only these two signals. Raising
        ``min_destinations`` above 20 would reject it, but that threshold would
        be fitted to this synthetic generator rather than chosen on principle,
        so the false positive is accepted and asserted here. If this test starts
        failing because the rule genuinely improved, update the README's numbers
        rather than deleting the case.
        """
        positives = horizontal(ports=300, hosts=36)
        negatives = [
            record_of(
                syn(src="10.7.0.9", dst=f"10.7.1.{i % 20 + 1}", dport=1000 + i),
                timestamp=1000.0 + i * 0.02,
            )
            for i in range(300)
        ]

        report = measure_accuracy(positives, negatives)

        assert report["false_positives"] > 0, "expected the documented ambiguity to remain"
        assert report["recall"] > 0.9, report
