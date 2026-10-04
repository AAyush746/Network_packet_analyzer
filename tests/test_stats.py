import pytest

from pktanalyzer.models import PacketRecord
from pktanalyzer.stats import TrafficStats


def make_packet(index: int, timestamp: float, src="10.0.0.1", dst="10.0.0.2",
                protocol="TCP", length=100, dst_port=443) -> PacketRecord:
    return PacketRecord(
        index=index, timestamp=timestamp, length=length,
        src_ip=src, dst_ip=dst, protocol=protocol, dst_port=dst_port, transport=protocol,
    )


class TestCounters:
    def test_empty_stats_are_safe_to_query(self):
        stats = TrafficStats()
        snapshot = stats.snapshot(now=100.0)

        assert snapshot.total_packets == 0
        assert snapshot.packets_per_second == 0.0
        assert snapshot.avg_packet_size == 0
        assert snapshot.duration == 0.0

    def test_totals_accumulate(self):
        stats = TrafficStats()
        for i in range(50):
            stats.observe(make_packet(i, 1000.0 + i * 0.01, length=200))

        snapshot = stats.snapshot(now=1000.49)
        assert snapshot.total_packets == 50
        assert snapshot.total_bytes == 10_000
        assert snapshot.avg_packet_size == 200

    def test_protocol_breakdown_is_ranked(self):
        stats = TrafficStats()
        stats.observe(make_packet(0, 100.0, protocol="TCP"))
        stats.observe(make_packet(1, 100.1, protocol="UDP"))
        stats.observe(make_packet(2, 100.2, protocol="TCP"))

        ranked = list(stats.snapshot(now=100.3).by_protocol.items())
        assert ranked[0] == ("TCP", 2)
        assert ranked[1] == ("UDP", 1)

    def test_unique_hosts_counts_both_ends(self):
        stats = TrafficStats()
        stats.observe(make_packet(0, 100.0, src="10.0.0.1", dst="10.0.0.2"))
        stats.observe(make_packet(1, 100.1, src="10.0.0.2", dst="10.0.0.3"))

        assert stats.snapshot(now=100.2).unique_hosts == 3

    def test_top_sources_and_ports_are_ranked(self):
        stats = TrafficStats()
        for i in range(5):
            stats.observe(make_packet(i, 100.0 + i * 0.01, src="10.0.0.9", dst_port=22))
        for i in range(2):
            stats.observe(make_packet(i, 100.1 + i * 0.01, src="10.0.0.1", dst_port=80))

        snapshot = stats.snapshot(now=100.2)
        assert snapshot.top_sources[0] == ("10.0.0.9", 5)
        assert snapshot.top_ports[0] == (22, 5)


class TestRollingRate:
    def test_rate_is_windowed_not_lifetime_averaged(self):
        """A burst then silence must decay, which a lifetime average never does."""
        stats = TrafficStats(pps_window=10.0)
        for i in range(100):
            stats.observe(make_packet(i, 1000.0 + i * 0.001))

        burst = stats.packets_per_second(now=1000.1)
        quiet = stats.packets_per_second(now=1030.0)

        assert burst > 50
        assert quiet == 0.0

    def test_rate_uses_elapsed_time_during_warmup(self):
        """Dividing by the full window would under-report the first burst."""
        stats = TrafficStats(pps_window=10.0)
        for i in range(10):
            stats.observe(make_packet(i, 100.0 + i * 0.1))

        rate = stats.packets_per_second(now=101.0)
        assert rate == pytest.approx(10.0, rel=0.2)

    def test_bytes_per_second_tracks_packet_sizes(self):
        stats = TrafficStats(pps_window=10.0)
        for i in range(20):
            stats.observe(make_packet(i, 200.0 + i * 0.01, length=1000))

        assert stats.bytes_per_second(now=200.2) > 0

    def test_window_is_memory_bounded(self):
        stats = TrafficStats(pps_window=1.0, max_samples=50)
        for i in range(5_000):
            stats.observe(make_packet(i, 1000.0 + i * 0.001))

        assert len(stats._window) <= 50

    def test_packets_outside_the_window_are_dropped(self):
        """At t=106 the 5s window covers [101, 106], so the t=100 packet is gone."""
        stats = TrafficStats(pps_window=5.0)
        stats.observe(make_packet(0, 100.0))

        assert stats.packets_per_second(now=103.0) > 0
        assert stats.packets_per_second(now=106.0) == 0.0


class TestLifecycle:
    def test_reset_clears_everything(self):
        stats = TrafficStats()
        for i in range(20):
            stats.observe(make_packet(i, 100.0 + i * 0.01))
        stats.alert_count = 4

        stats.reset()
        snapshot = stats.snapshot(now=200.0)

        assert snapshot.total_packets == 0
        assert snapshot.total_bytes == 0
        assert snapshot.by_protocol == {}
        assert snapshot.active_alerts == 0

    def test_restore_rebuilds_counters_from_scratch(self):
        records = [make_packet(i, 100.0 + i * 0.01) for i in range(30)]

        stats = TrafficStats()
        stats.restore(records)
        rebuilt = stats.snapshot(now=100.3)

        assert rebuilt.total_packets == 30
        assert rebuilt.unique_hosts == 2

    def test_observe_never_raises_on_broken_record(self):
        class Exploding:
            @property
            def timestamp(self):
                raise RuntimeError("boom")

            length = 0
            protocol = ""
            src_ip = ""
            dst_ip = ""
            dst_port = None

        stats = TrafficStats()
        stats.observe(Exploding())  # must not propagate
        assert stats.snapshot().total_packets == 0

    def test_observe_many_matches_repeated_observe(self):
        records = [make_packet(i, 100.0 + i * 0.01) for i in range(10)]

        batched, one_by_one = TrafficStats(), TrafficStats()
        batched.observe_many(records)
        for record in records:
            one_by_one.observe(record)

        assert batched.snapshot(now=100.1).total_packets == one_by_one.snapshot(now=100.1).total_packets
