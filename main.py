#!/usr/bin/env python3
"""Entry point: ``python main.py`` or ``sudo python main.py`` to capture."""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pktanalyzer",
        description="Live network packet analyzer with protocol dissection, "
                    "traffic statistics and anomaly detection.",
    )
    parser.add_argument("-i", "--iface", help="interface to capture on")
    parser.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 443'")
    parser.add_argument("--demo", action="store_true",
                        help="run on synthetic traffic instead of a real interface")
    parser.add_argument("--capture", action="store_true",
                        help="capture headlessly for --duration seconds and print stats")
    parser.add_argument("--duration", type=float, default=10.0, metavar="SEC",
                        help="seconds to capture for in --capture mode (default: 10)")
    parser.add_argument("--export", metavar="PATH",
                        help="write the capture to a .pcap/.csv/.json file on exit")
    args = parser.parse_args(argv)

    if args.demo:
        return _demo(args)

    if args.capture:
        return _headless_capture(args)

    from pktanalyzer.ui import main as gui_main

    if args.iface:
        print(f"note: start the GUI and choose {args.iface!r} in the interface dropdown")
    if args.filter:
        print(f"note: BPF filter {args.filter!r} can be pasted into the filter box")
    gui_main()
    return 0


def _headless_capture(args: argparse.Namespace) -> int:
    """Capture for a fixed duration, report what was seen, then exit.

    Exists so throughput can be measured against a known generator (iperf3, for
    example) without a GUI or a human reading counters off a table. The GUI is
    a better way to *explore* traffic; this is the better way to *measure* it.
    """
    import time

    from pktanalyzer.capture import CaptureEngine, list_interfaces, validate_bpf
    from pktanalyzer.detect import DetectionEngine
    from pktanalyzer.export import save
    from pktanalyzer.stats import TrafficStats

    if args.filter:
        try:
            validate_bpf(args.filter)
        except Exception as error:
            print(f"invalid BPF filter {args.filter!r}: {error}")
            return 2

    iface = args.iface
    if not iface:
        available = [name for name in list_interfaces() if name != "lo"]
        if not available:
            print("no capture interface found; pass --iface")
            return 2
        iface = available[0]
        print(f"using interface {iface!r} (pass --iface to choose another)")

    stats, detector = TrafficStats(), DetectionEngine()
    engine = CaptureEngine(
        iface=iface, bpf=args.filter, stats=stats, detector=detector
    )

    print(f"capturing on {iface} for {args.duration:g}s"
          f"{f' [filter: {args.filter}]' if args.filter else ''} ...")
    engine.start()
    # Capture happens on a background thread, so a permissions failure surfaces
    # in capture_stats rather than as an exception here. Without this check the
    # command prints a plausible-looking zero-packet report after failing.
    deadline = time.perf_counter() + 2.0
    while time.perf_counter() < deadline and not engine.capture_stats.errors:
        if engine.capture_stats.packets_seen:
            break
        time.sleep(0.05)

    if engine.capture_stats.errors and not engine.capture_stats.packets_seen:
        engine.stop()
        first = engine.capture_stats.errors[0]
        print(f"\ncapture failed: {first}")
        if "permitted" in first.lower() or "permission" in first.lower():
            print("hint: live capture needs root or CAP_NET_RAW -- try: sudo python main.py --capture")
        return 1

    started = time.perf_counter()
    try:
        while time.perf_counter() - started < args.duration:
            time.sleep(0.1)
            # Drain continuously: the queue is bounded and the capture thread
            # drops rather than blocks, so an undrained queue would undercount.
            engine.drain(max_items=2000)
    except KeyboardInterrupt:
        print("\ninterrupted")
    finally:
        engine.stop()
        engine.drain(max_items=10_000)
    elapsed = time.perf_counter() - started

    snapshot = stats.snapshot()
    cs = engine.capture_stats
    print(f"\nelapsed          : {elapsed:.2f}s")
    print(f"packets analysed : {snapshot.total_packets:,}")
    print(f"throughput       : {snapshot.total_packets / elapsed:,.0f} packets/sec")
    print(f"bytes            : {snapshot.total_bytes:,}"
          f"  ({snapshot.total_bytes * 8 / elapsed / 1e6:.1f} Mbit/s of frame data)")
    print(f"packets seen     : {cs.packets_seen:,}")
    print(f"queue drops      : {cs.packets_dropped:,}")
    print(f"decode failures  : {cs.decode_failures:,}")
    print(f"protocols        : {snapshot.by_protocol}")
    print(f"unique hosts     : {snapshot.unique_hosts}")
    print(f"alerts           : {detector.total_alerts}")
    for message in cs.errors[:5]:
        print(f"error            : {message}")

    if args.export:
        records, _ = engine.drain(max_items=10_000)
        if records:
            save(records, args.export)
            print(f"exported         : {len(records):,} records -> {args.export}")
        else:
            print("exported         : nothing (capture buffer already drained)")
    return 0


def _demo(args: argparse.Namespace) -> int:
    """Headless run over synthetic traffic, useful without capture privileges."""
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw

    from pktanalyzer.capture import replay
    from pktanalyzer.detect import DetectionEngine
    from pktanalyzer.export import save
    from pktanalyzer.stats import TrafficStats

    frames = []
    for i in range(40):
        frames.append(Ether() / IP(src=f"10.0.0.{i % 5 + 1}", dst="93.184.216.34")
                      / TCP(sport=40000 + i, dport=443, flags="PA") / Raw(load=b"GET / HTTP/1.1\r\n"))
        frames.append(Ether() / IP(src=f"10.0.0.{i % 5 + 1}", dst="8.8.8.8")
                      / UDP(sport=53000 + i, dport=53)
                      / DNS(rd=1, qd=DNSQR(qname="example.com")))

    # A horizontal scan: many ports across many hosts, which is the signature the
    # rule actually requires. Sweeping many ports on a *single* host is service
    # discovery and is deliberately not flagged.
    for i in range(60):
        frames.append(
            Ether() / IP(src="10.0.0.66", dst=f"10.0.1.{i % 20 + 1}")
            / TCP(sport=40000, dport=1000 + i, flags="S")
        )

    # Deliberately include a benign single-host port sweep to show it is *not*
    # reported -- the same port count that would be alarming spread over hosts.
    for port in range(1, 30):
        frames.append(Ether() / IP(src="10.0.0.99", dst="10.0.0.1") / TCP(dport=port, flags="S"))

    frames.append(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())
    frames.append(Ether() / ARP(psrc="10.0.0.1", pdst="10.0.0.254"))

    records = replay(frames)
    stats, detector = TrafficStats(), DetectionEngine()
    for record in records:
        stats.observe(record)
        for alert in detector.inspect(record):
            print(alert)

    snapshot = stats.snapshot()
    print(f"\npackets={snapshot.total_packets}  bytes={snapshot.total_bytes:,}  "
          f"pps={snapshot.packets_per_second}  hosts={snapshot.unique_hosts}")
    print(f"protocols={snapshot.by_protocol}")
    print(f"top talkers={snapshot.top_sources[:3]}")
    print(f"alerts={detector.total_alerts}")

    if args.export:
        print(f"\nwrote {save(records, args.export)} packets to {args.export}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
