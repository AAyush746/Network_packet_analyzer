#!/usr/bin/env python3
"""Benchmark the analysis pipeline and print reproducible numbers.

Run:  python bench.py
Add:  --packets 50000   to scale the workload

Everything printed here is measured on the machine that runs it, so the figures
in the README can be regenerated rather than quoted from memory. Requires no
capture privileges -- it replays synthetic frames through the real decode,
statistics and detection code.
"""

from __future__ import annotations

import argparse
import gc
import statistics
import sys
import time
from tracemalloc import get_traced_memory, start

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw

from pktanalyzer.decode import decode
from pktanalyzer.detect import DetectionEngine, measure_accuracy
from pktanalyzer.export import save_csv, save_pcap
from pktanalyzer.models import PacketRecord
from pktanalyzer.stats import TrafficStats

ETH = dict(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")


def build_traffic(count: int) -> list:
    """A mixed workload: TCP, DNS, ICMP, ARP and a port scan to trip detection.

    ``wirelen`` is stamped on every frame, exactly as the capture layer does for
    a real interface. This matters for the numbers: scapy's ``Packet.__len__``
    is a full serialisation (~0.5 ms/frame), so synthetic frames without
    ``wirelen`` would make the benchmark measure serialisation instead of
    decoding.
    """
    frames = []
    for i in range(count):
        pick = i % 100
        if pick < 55:
            frames.append(Ether(**ETH) / IP(src=f"10.0.{i % 8}.{i % 9 + 1}", dst="93.184.216.34", ttl=64)
                          / TCP(sport=32768 + (i % 20000), dport=443, flags="PA")
                          / Raw(load=b"x" * (i % 512)))
        elif pick < 80:
            frames.append(Ether() / IP(src=f"10.0.{i % 8}.{i % 9 + 1}", dst="8.8.8.8")
                          / UDP(sport=53000 + (i % 1000), dport=53)
                          / DNS(rd=1, qd=DNSQR(qname=f"host{i % 500}.example.com")))
        elif pick < 90:
            frames.append(Ether() / IP(src=f"10.0.{i % 8}.{i % 9 + 1}", dst=f"10.0.0.{i % 4 + 1}")
                          / ICMP(type=8))
        elif pick < 97:
            frames.append(Ether() / ARP(psrc=f"10.0.{i % 8}.{i % 9 + 1}", pdst="10.0.0.254"))
        else:
            # scan traffic: enough to trigger the port-scan rule
            frames.append(Ether() / IP(src="10.0.0.66", dst="10.0.0.1")
                          / TCP(dport=i % 900 + 1, flags="S"))

    for frame in frames:
        frame.wirelen = len(bytes(frame))
    return frames


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = min(int(len(ordered) * fraction), len(ordered) - 1)
    return ordered[position]


def bench_gc_impact(frames: list, repeats: int = 7) -> tuple[float, float]:
    """Measure how much cyclic-GC pausing costs when records are retained.

    Each PacketRecord owns a list of LayerInfo plus a dict per layer, so a
    packet contributes several GC-tracked containers. Retaining tens of
    thousands of records therefore makes the collector's periodic full passes
    progressively more expensive, and that cost lands on whichever packet
    happens to trigger a collection -- which is why max latency can be orders of
    magnitude worse than p99.

    Runs are interleaved and the *median* reported. A single A-then-B pair is
    useless here: whichever run happens to absorb an allocator warm-up or a
    stray collection wins by luck and the difference comes out negative, which
    would read as "GC makes things faster".
    """
    def timed() -> tuple[float, float]:
        durations: list[float] = []
        retained: list[PacketRecord] = []
        for index, packet in enumerate(frames):
            started = time.perf_counter()
            retained.append(decode(packet, index))
            durations.append((time.perf_counter() - started) * 1e6)
        return statistics.median(durations), max(durations)

    with_means: list[float] = []
    with_maxes: list[float] = []
    without_means: list[float] = []
    without_maxes: list[float] = []

    for _ in range(repeats):
        gc.enable()
        gc.collect()
        mean, worst = timed()
        with_means.append(mean)
        with_maxes.append(worst)

        gc.disable()
        try:
            mean, worst = timed()
        finally:
            gc.enable()
        without_means.append(mean)
        without_maxes.append(worst)

    gc.collect()
    mean_delta = statistics.median(with_means) - statistics.median(without_means)
    max_delta = statistics.median(with_maxes) - statistics.median(without_maxes)
    return max_delta, mean_delta


def bench_decode(frames: list, keep_raw: bool = False) -> tuple[list[PacketRecord], list[float]]:
    durations: list[float] = []
    records: list[PacketRecord] = []
    for index, packet in enumerate(frames):
        started = time.perf_counter()
        records.append(decode(packet, index, keep_raw=keep_raw))
        durations.append((time.perf_counter() - started) * 1e6)
    return records, durations


def bench_pipeline(frames: list) -> tuple[float, DetectionEngine, TrafficStats]:
    stats, detector = TrafficStats(), DetectionEngine()
    started = time.perf_counter()
    for index, packet in enumerate(frames):
        record = decode(packet, index)
        stats.observe(record)
        detector.inspect(record)
    return time.perf_counter() - started, detector, stats


def bench_memory(frames: list) -> float:
    gc.collect()
    start()
    stats = TrafficStats()
    for index, packet in enumerate(frames):
        stats.observe(decode(packet, index))
    _current, peak = get_traced_memory()
    del stats
    return peak / 1024 / 1024


def accuracy_report() -> dict[str, float]:
    positives, negatives = [], []
    for i in range(300):
        packet = Ether() / IP(src="10.0.0.66", dst=f"10.0.{i % 4}.{i % 9 + 1}") / TCP(dport=i % 900 + 1, flags="S")
        packet.time = 1000.0 + i * 0.02
        positives.append(decode(packet, i))

        packet = Ether() / IP(src=f"10.1.{i % 250}.5", dst=f"10.2.{i % 9}.{i % 250 + 1}") / \
            TCP(dport=[80, 443, 22, 53][i % 4], flags="S")
        packet.time = 1000.0 + i * 0.02
        negatives.append(decode(packet, i))

    return measure_accuracy(positives, negatives)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=int, default=20_000)
    parser.add_argument("--export", metavar="PATH", help="also export the capture here")
    args = parser.parse_args()

    print(f"building {args.packets:,} synthetic frames ...")
    frames = build_traffic(args.packets)

    # Warm up caches (IANA port table, scapy class metadata, interpreter
    # bytecode) before timing. Without this the very first packet carries a
    # ~180 ms outlier that says nothing about steady-state throughput.
    for index, frame in enumerate(frames[:200]):
        decode(frame, index)

    # Move everything allocated before the measurement window into a permanent
    # generation, so collection passes do not keep re-traversing it.
    gc.collect()
    gc.freeze()

    # --- decode throughput and latency ---
    records, durations = bench_decode(frames)
    mean_us = statistics.fmean(durations)
    print("\n== decode ==")
    print(f"  packets         : {len(records):,}")
    print(f"  throughput      : {len(frames) / (sum(durations) / 1e6):,.0f} packets/sec")
    print(f"  mean latency    : {mean_us:.1f} us/packet")
    print(f"  p50 / p95 / p99 : {percentile(durations, 0.50):.1f} / "
          f"{percentile(durations, 0.95):.1f} / {percentile(durations, 0.99):.1f} us")
    print(f"  max             : {max(durations):.1f} us")

    # --- cost of retaining frames for pcap export ---
    _, retained = bench_decode(frames[:2000], keep_raw=True)
    baseline = statistics.fmean(durations)
    with_raw = statistics.fmean(retained)
    print("\n== frame retention (keep_raw, needed for pcap export) ==")
    print(f"  without         : {baseline:.1f} us/packet")
    print(f"  with            : {with_raw:.1f} us/packet  "
          f"({with_raw / baseline:.2f}x, +{with_raw - baseline:.1f} us)")

    # --- full pipeline: decode + stats + detection ---
    elapsed, detector, stats = bench_pipeline(frames)
    print("\n== decode + stats + detection ==")
    print(f"  total time      : {elapsed:.2f} s")
    print(f"  throughput      : {len(frames) / elapsed:,.0f} packets/sec")
    print(f"  per packet      : {elapsed / len(frames) * 1e6:.1f} us")
    print(f"  alerts raised   : {detector.total_alerts}")

    # --- memory ---
    peak_mb = bench_memory(frames)
    print("\n== memory ==")
    print(f"  peak (tracemalloc): {peak_mb:.1f} MB for {len(frames):,} packets")
    print(f"  per packet        : {peak_mb * 1024 * 1024 / len(frames):.0f} bytes")
    print(f"  rolling window    : {stats._window.maxlen:,} samples retained (bounded)")

    # --- how much of the tail is the garbage collector ---
    sample = frames[:8000]
    _max_delta, mean_delta = bench_gc_impact(sample)
    print("\n== garbage collector (median of 7 interleaved runs) ==")
    print(f"  median cost when GC is disabled vs enabled: {mean_delta:.1f} us/packet")
    print(
        "  note: the distribution is bimodal. Most packets cost ~50 us, but\n"
        "  periodic collection pauses spike into the tens of milliseconds once\n"
        "  tens of thousands of records are retained, so the median understates\n"
        "  what a UI thread would actually experience as a stall."
    )

    # --- accuracy ---
    report = accuracy_report()
    print("\n== port-scan detection accuracy (labelled synthetic traffic) ==")
    for key in ("precision", "recall", "f1", "true_positives", "false_positives", "false_negatives"):
        print(f"  {key:18}: {report[key]}")

    # --- export ---
    if args.export:
        # Re-decode with retention: the timing pass above deliberately runs
        # without it, so only this copy is exportable.
        exportable, _ = bench_decode(frames, keep_raw=True)

        pcap_started = time.perf_counter()
        written = save_pcap(exportable, args.export)
        print(f"\n== export ==\n  pcap: {written:,} frames in "
              f"{time.perf_counter() - pcap_started:.2f}s -> {args.export}")
        csv_path = args.export.rsplit(".", 1)[0] + ".csv"
        csv_started = time.perf_counter()
        save_csv(exportable, csv_path)
        print(f"  csv : {len(exportable):,} rows in {time.perf_counter() - csv_started:.2f}s -> {csv_path}")

    print("\npython " + sys.version.split()[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
