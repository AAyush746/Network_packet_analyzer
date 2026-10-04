#!/usr/bin/env python3
"""Entry point: ``python main.py`` or ``sudo python main.py`` to capture."""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="pktanalyzer",
        description="Live network packet analyzer with protocol dissection, "
                    "traffic statistics and anomaly detection.",
    )
    parser.add_argument("-i", "--iface", help="interface to capture on")
    parser.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 443'")
    parser.add_argument("--demo", action="store_true",
                        help="run on synthetic traffic instead of a real interface")
    parser.add_argument("--export", metavar="PATH",
                        help="write the capture to a .pcap/.csv/.json file on exit")
    args = parser.parse_args()

    if args.demo:
        return _demo(args)

    from pktanalyzer.ui import main as gui_main

    if args.iface:
        print(f"note: start the GUI and choose {args.iface!r} in the interface dropdown")
    if args.filter:
        print(f"note: BPF filter {args.filter!r} can be pasted into the filter box")
    gui_main()
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
    for port in range(1, 40):  # a scan to trip the detector
        frames.append(Ether() / IP(src="10.0.0.66", dst="10.0.0.1") / TCP(dport=port, flags="S"))
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
