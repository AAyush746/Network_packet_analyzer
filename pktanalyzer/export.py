"""Persistence: pcap round-trip plus CSV and JSON export.

The pcap path is what makes this a real analyzer rather than a live-only toy:
a capture you can reload in Wireshark is evidence, a screenshot is not.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from pathlib import Path

from scapy.utils import PcapReader, wrpcap

from .models import PacketRecord

CSV_COLUMNS = [
    "index", "timestamp", "length", "src_mac", "dst_mac",
    "src_ip", "src_port", "dst_ip", "dst_port",
    "protocol", "service", "ttl", "flags", "info",
]


def _validate_format(suffix: str) -> str:
    fmt = suffix.lower().lstrip(".")
    if fmt not in {"pcap", "cap", "json", "csv"}:
        raise ValueError(f"unsupported format: {suffix} (use .pcap, .csv or .json)")
    return "pcap" if fmt == "cap" else fmt


def save_pcap(records: Iterable[PacketRecord], path: str | Path) -> int:
    """Write raw frames to a pcap file. Returns the number saved.

    Raises ValueError when no frame can be written. Returning 0 instead would
    leave the caller believing it had written a capture file that does not
    exist, which is exactly the kind of silent data loss this module exists to
    avoid.
    """
    # Materialise once: the function is typed as Iterable and needs two passes.
    # A generator would be exhausted by the first one.
    candidates = list(records)
    if not candidates:
        # Nothing was captured, so there is nothing to write. This is not an
        # error -- the caller passed an empty set deliberately.
        return 0

    # Frames captured without a link-layer header cannot go into a pcap: the
    # file format stores one link type for the whole file and has nowhere to
    # record which one each frame used. The flag is captured at decode time --
    # re-deriving it from ``raw`` would mean parsing the bytes again, and
    # ``Ether in some_bytes`` silently means byte-substring search, not a
    # layer check.
    writable = [
        record.raw for record in candidates if record.raw and record.has_link_layer
    ]

    if not writable:
        if not any(record.raw for record in candidates):
            raise ValueError(
                "these records hold no frame bytes; a pcap needs raw frames. "
                "Decode with keep_raw=True (CaptureEngine(keep_raw=True)) or "
                "load_pcap(path, keep_raw=True)."
            )
        raise ValueError("no Ethernet frames to write; pcap needs a link-layer header")

    wrpcap(str(path), writable)
    return len(writable)


def load_pcap(path: str | Path, keep_raw: bool = False) -> list[PacketRecord]:
    """Read a pcap and decode every frame.

    ``keep_raw`` is off by default because serialising every frame is the single
    most expensive step in decoding. Turn it on when the records are destined
    for a later save, otherwise a load-then-save round trip cannot work.
    """
    from .decode import decode

    records: list[PacketRecord] = []
    with PcapReader(str(path)) as reader:
        for index, packet in enumerate(reader):
            try:
                records.append(decode(packet, index, keep_raw=keep_raw))
            except Exception:
                continue
    return records


def save_csv(records: Iterable[PacketRecord], path: str | Path) -> int:
    rows = list(records)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for record in rows:
            writer.writerow([
                record.index,
                f"{record.timestamp:.6f}",
                record.length,
                record.src_mac,
                record.dst_mac,
                record.src_ip,
                record.src_port if record.src_port is not None else "",
                record.dst_ip,
                record.dst_port if record.dst_port is not None else "",
                record.protocol,
                record.service,
                record.ttl if record.ttl is not None else "",
                record.flags,
                record.info,
            ])
    return len(rows)


def save_json(records: Iterable[PacketRecord], path: str | Path) -> int:
    """Write the full decoded structure, including the layer tree."""
    rows = list(records)
    payload = [
        {
            "index": r.index,
            "timestamp": r.timestamp,
            "length": r.length,
            "src_mac": r.src_mac,
            "dst_mac": r.dst_mac,
            "src_ip": r.src_ip,
            "src_port": r.src_port,
            "dst_ip": r.dst_ip,
            "dst_port": r.dst_port,
            "protocol": r.protocol,
            "service": r.service,
            "ttl": r.ttl,
            "flags": r.flags,
            "info": r.info,
            "layers": [{"name": layer.name, "fields": layer.fields} for layer in r.layers],
            "payload_hex": r.payload_hex,
            "payload_ascii": r.payload_ascii,
        }
        for r in rows
    ]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return len(rows)


def save(records: Iterable[PacketRecord], path: str | Path) -> int:
    """Dispatch on the file extension."""
    target = Path(path)
    fmt = _validate_format(target.suffix)
    if fmt == "pcap":
        return save_pcap(records, target)
    if fmt == "csv":
        return save_csv(records, target)
    return save_json(records, target)


def load(path: str | Path, keep_raw: bool = False) -> list[PacketRecord]:
    """Dispatch on the file extension. Only pcap can be read back losslessly."""
    target = Path(path)
    fmt = _validate_format(target.suffix)
    if fmt == "pcap":
        return load_pcap(target, keep_raw=keep_raw)
    raise ValueError(f"cannot import {target.suffix}; only .pcap can be reloaded")


def pcap_frame_count(path: str | Path) -> int:
    with PcapReader(str(path)) as reader:
        return sum(1 for _ in reader)


def is_pcap(path: str | Path) -> bool:
    """Validate the pcap magic number rather than trusting the extension."""
    try:
        with open(path, "rb") as handle:
            magic = handle.read(4)
    except OSError:
        return False
    return magic in {
        b"\xd4\xc3\xb2\xa1",  # little endian
        b"\xa1\xb2\xc3\xd4",  # big endian
        b"\x4d\x3c\xb2\xa1",  # nanosecond little endian
        b"\xa1\xb2\x3c\x4d",  # nanosecond big endian
    }
