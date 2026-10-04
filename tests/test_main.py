"""Entry point tests.

``main.py`` holds the only code that decides whether a capture actually
started, so those paths are worth covering. The success path is mocked because
a suite that needs root would never run in CI.
"""

from __future__ import annotations

from scapy.all import IP, TCP, Ether

import main as entry
from pktanalyzer import capture as capture_module
from pktanalyzer.capture import CaptureEngine


class TestDemoMode:
    def test_demo_runs_headless_and_reports(self, capsys):
        assert entry.main(["--demo"]) == 0

        out = capsys.readouterr().out
        assert "packets=" in out
        assert "protocols=" in out
        assert "top talkers=" in out

    def test_demo_detects_the_horizontal_scan(self, capsys):
        entry.main(["--demo"])

        out = capsys.readouterr().out
        assert "port_scan" in out
        assert "10.0.0.66" in out, "the scan source should be named in the alert"

    def test_demo_does_not_flag_the_benign_single_host_sweep(self, capsys):
        """The demo includes both shapes so the distinction is visible."""
        entry.main(["--demo"])

        out = capsys.readouterr().out
        alerts, _, talkers = out.partition("top talkers=")
        assert "10.0.0.99" not in alerts, "a sweep on one host is not a scan"
        assert "10.0.0.99" in talkers, "but it is still counted as traffic"


class TestFilterValidation:
    def test_invalid_filter_is_rejected_before_opening_a_socket(self, capsys):
        assert entry.main(["--capture", "--filter", "not a valid filter at all"]) == 2

        assert "invalid BPF filter" in capsys.readouterr().out


class TestCaptureLifecycle:
    def test_permission_failure_is_reported_not_raised(self, monkeypatch, capsys):
        """A capture that never started must not print a plausible zero report."""

        class Failing(CaptureEngine):
            def start(self):
                self.capture_stats.errors.append(
                    "permission denied: raw capture needs root (Operation not permitted)"
                )

            def stop(self, timeout=2.0):
                pass

            def drain(self, max_items=500):
                return [], []

        monkeypatch.setattr(capture_module, "CaptureEngine", Failing)

        assert entry.main(["--capture", "--iface", "lo", "--duration", "1"]) == 1

        out = capsys.readouterr().out
        assert "capture failed" in out
        assert "sudo" in out, "should tell the user how to fix it"
        assert "packets analysed" not in out, "must not print stats for a failed capture"

    def test_successful_capture_reports_a_rate(self, monkeypatch, capsys):
        class Working(CaptureEngine):
            def start(self):
                for _ in range(5):
                    self._handle(
                        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80)
                    )

            def stop(self, timeout=2.0):
                pass

        monkeypatch.setattr(capture_module, "CaptureEngine", Working)

        assert entry.main(["--capture", "--iface", "lo", "--duration", "0.2"]) == 0

        out = capsys.readouterr().out
        assert "packets analysed : 5" in out
        assert "packets/sec" in out
        assert "queue drops" in out

    def test_duration_is_respected(self, monkeypatch, capsys):
        import time

        class Working(CaptureEngine):
            def start(self):
                self._handle(Ether() / IP() / TCP())

            def stop(self, timeout=2.0):
                pass

        monkeypatch.setattr(capture_module, "CaptureEngine", Working)

        started = time.perf_counter()
        entry.main(["--capture", "--iface", "lo", "--duration", "1"])
        elapsed = time.perf_counter() - started

        assert 1.0 <= elapsed < 4.0, f"took {elapsed:.1f}s for a 1s capture"
