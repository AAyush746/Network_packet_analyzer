"""Packet dissection.

The original implementation branched on layer presence:

    if packet.haslayer(TCP):  ...
    elif packet.haslayer(UDP): ...

That means every protocol you have not thought of yet is silently dropped.
Instead we walk scapy's payload chain once and visit every layer, so adding
support for a new protocol becomes a data change, not a code change.

Performance notes (see ``bench.py``). Two things dominated the first version:

1. ``packet[layer_class]`` per layer *and* ``packet.haslayer(...)`` per field.
   Layer lookups are not free, and ``getattr`` on a field scapy has not set
   raises internally, so a "missing" field cost an exception. Now the chain is
   walked exactly once with ``.payload``, field-name lists are cached per
   layer class, and the layers we care about are collected during that same
   walk instead of being looked up again.
2. ``bytes(packet)`` was called for every packet to keep a copy for pcap
   export, even though most captures are never exported. Retention is now the
   caller's decision via ``keep_raw``.
"""

from __future__ import annotations

import socket
import time

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import NoPayload, Packet, Raw

from .models import MAX_PAYLOAD_PREVIEW, MAX_PAYLOAD_STORE, LayerInfo, PacketRecord

# --- protocol registries -----------------------------------------------------

IP_PROTOCOLS: dict[int, str] = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
    41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6",
    89: "OSPF", 132: "SCTP",
}

SERVICES: dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "SYSLOG", 587: "SMTP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MYSQL",
    3389: "RDP", 5060: "SIP", 5432: "POSTGRES", 6379: "REDIS",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MONGODB",
}

MAX_FIELD_CHARS = 40
MAX_LIST_ITEMS = 2

# Guards against a malformed chain that loops back on itself.
MAX_LAYERS = 32

# Layers worth keeping a direct reference to while walking.
_INTEREST: dict[type, str] = {
    Ether: "ether", IP: "ip", IPv6: "ipv6", ARP: "arp",
    TCP: "tcp", UDP: "udp", Raw: "raw",
}

# Layers whose own bytes are a header, not payload. Used when deciding whether a
# frame with no Raw layer carries inspectable content: if the innermost layer is
# one of these, the frame has no application payload to expose.
_PAYLOAD_EXCLUDED = frozenset(
    {"Ether", "IP", "IPv6", "ARP", "ICMP", "ICMPv6", "TCP", "UDP", "SCTP"}
)

# Field-name lists per layer class. fields_desc is fixed for a class, so
# rebuilding this on every packet was pure overhead.
_FIELD_NAMES: dict[type, tuple[str, ...]] = {}


# IANA service names are looked up with getservbyport, which is a syscall and
# slow enough to dominate the first few packets. Ports repeat constantly, so a
# dict is the whole fix.
_PORT_NAME_CACHE: dict[int, str] = {}


def _port_label(port: int) -> str:
    label = _PORT_NAME_CACHE.get(port)
    if label is None:
        try:
            label = socket.getservbyport(port, "tcp")
        except OSError:
            label = f"PORT-{port}"
        _PORT_NAME_CACHE[port] = label
    return label


def service_for(port: int | None) -> str:
    """Display label for a single port. Falls back to the IANA name, then PORT-xxx."""
    if port is None:
        return ""
    if port in SERVICES:
        return SERVICES[port]
    return _port_label(port)


def resolve_service(src_port: int | None, dst_port: int | None) -> str:
    """Pick the most meaningful service label for a 5-tuple.

    Both ports must be considered: a DNS *reply* arrives as sport=53 dport=41234,
    so looking only at the destination would label every reply PORT-41234.
    Prefers a registry hit on either port over an IANA guess.
    """
    candidates = [port for port in (dst_port, src_port) if port is not None]
    for port in candidates:
        if port in SERVICES:
            return SERVICES[port]
    for port in candidates:
        label = _PORT_NAME_CACHE.get(port)
        if label is not None and not label.startswith("PORT-"):
            return label
    return _port_label(candidates[0]) if candidates else ""


def _truncate(text: str) -> str:
    return text if len(text) <= MAX_FIELD_CHARS else text[:MAX_FIELD_CHARS] + "..."


def _try_text(raw: bytes) -> str | None:
    """Decode bytes as ASCII if they really are text (DNS qnames, HTTP headers)."""
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if text and all(32 <= ord(char) < 127 or char in "\r\n\t" for char in text):
        collapsed = text.replace("\r\n", "\\r\\n").replace("\n", "\\n").replace("\r", "\\r")
        return _truncate(collapsed)
    return None


def _render_packet_brief(packet: Packet) -> str:
    """Render a sub-record such as DNSQR as ``DNSQR qname=example.com``."""
    parts: list[str] = []
    for name in _field_names(type(packet))[:3]:
        value = getattr(packet, name, None)
        rendered = _render_value(value)
        if rendered:
            parts.append(f"{name}={rendered}")
    joined = " ".join(parts)
    return _truncate(joined) if joined else type(packet).__name__


def _render_value(value: object) -> str:
    """Make any scapy field printable and bounded, so one huge field cannot stall the UI.

    Two cases matter for correctness, not just looks:
      * list-valued fields, where scapy packs sub-records (DNSQR, TCP options);
        ``str(list)`` would byte-stringify them and hide the real content
      * bytes that are actually text, which naive handling reduces to ``<12 bytes>``
    """
    if isinstance(value, (bytes, bytearray)):
        return _try_text(bytes(value)) or f"<{len(value)} bytes>"

    if isinstance(value, Packet):
        return _render_packet_brief(value)

    if isinstance(value, (list, tuple)):
        if not value:
            return ""
        rendered = [_render_value(item) for item in value[:MAX_LIST_ITEMS]]
        text = ", ".join(part for part in rendered if part)
        if len(value) > MAX_LIST_ITEMS:
            text += f", +{len(value) - MAX_LIST_ITEMS} more"
        return text

    return _truncate(str(value))


def _field_names(layer_class: type) -> tuple[str, ...]:
    """Cached field names for a layer class, excluding the raw payload blob."""
    cached = _FIELD_NAMES.get(layer_class)
    if cached is None:
        try:
            cached = tuple(d.name for d in layer_class.fields_desc if d.name != "load")
        except AttributeError:
            cached = ()
        _FIELD_NAMES[layer_class] = cached
    return cached


def _layer_fields(layer: Packet) -> dict[str, str]:
    """Extract the printable fields of one layer."""
    names = _field_names(type(layer))
    if not names:
        return {}
    fields: dict[str, str] = {}
    for name in names:
        value = getattr(layer, name, None)
        if value is None:
            continue
        rendered = _render_value(value)
        if rendered:
            fields[name] = rendered
    return fields


def _dissect(packet: Packet) -> tuple[list[LayerInfo], dict[str, Packet]]:
    """Walk the payload chain once, collecting layer views and useful references."""
    layers: list[LayerInfo] = []
    refs: dict[str, Packet] = {}
    layer: Packet | None = packet
    innermost: Packet | None = None

    for _ in range(MAX_LAYERS):
        if layer is None or isinstance(layer, NoPayload):
            break
        cls = type(layer)

        key = _INTEREST.get(cls)
        if key is None:
            # Subclasses exist (scapy registers several); fall back to a scan.
            for base, candidate in _INTEREST.items():
                if isinstance(layer, base):
                    key = candidate
                    break
        if key is not None and key not in refs:
            refs[key] = layer

        layers.append(LayerInfo(name=cls.__name__, fields=_layer_fields(layer)))
        innermost = layer

        payload = layer.payload
        if payload is layer or isinstance(payload, NoPayload):
            break
        layer = payload

    # Captured while walking, so the caller never has to traverse again.
    refs["innermost"] = innermost if innermost is not None else packet

    return layers, refs


def _payload_preview(payload: bytes) -> tuple[str, str]:
    """Return (hex, printable-ascii) previews, safely truncated."""
    clipped = payload[:MAX_PAYLOAD_PREVIEW]
    hex_view = clipped.hex(" ")
    ascii_view = "".join(chr(b) if 32 <= b < 127 else "." for b in clipped)
    return hex_view, ascii_view


def _describe(refs: dict[str, Packet], protocol: str) -> str:
    """Human-readable summary for the Info column."""
    tcp = refs.get("tcp")
    if tcp is not None:
        return f"TCP [{tcp.flags}] seq={tcp.seq}"

    udp = refs.get("udp")
    if udp is not None:
        # Synthetic packets leave `len` unset; fall back to observed payload.
        declared = getattr(udp, "len", None)
        length = declared if declared else len(udp.payload)
        return f"UDP len={length}"

    arp = refs.get("arp")
    if arp is not None:
        return f"ARP op={arp.op}"

    if protocol in ("ICMP", "ICMPv6"):
        ip = refs.get("ip")
        if ip is not None:
            return f"{protocol} type={ip.type} code={ip.code}"

    return protocol or "unknown"


def decode(packet: Packet, index: int = 0, keep_raw: bool = False) -> PacketRecord:
    """Convert a scapy packet into a PacketRecord.

    Never raises: a malformed frame yields a partial record rather than
    killing the capture thread.

    ``keep_raw`` retains a serialised copy of the frame so it can be written to
    a pcap later. Serialisation is the single most expensive step here, so
    leave it off for a live view that will never be exported.
    """
    try:
        timestamp = float(packet.time)
    except Exception:
        timestamp = time.time()

    try:
        wirelen = int(packet.wirelen)
    except Exception:
        wirelen = 0
    if not wirelen:
        # Captured frames always carry wirelen, so this only fires for
        # synthetic packets built in tests or the demo. Beware: scapy's
        # Packet.__len__ is defined as len(bytes(self)), i.e. a full
        # serialisation costing ~0.5 ms per frame -- roughly the entire decode
        # budget. Never hoist this into the common path.
        try:
            wirelen = len(packet)
        except Exception:
            wirelen = 0

    record = PacketRecord(index=index, timestamp=timestamp, length=wirelen)
    record.layers, refs = _dissect(packet)

    ether = refs.get("ether")
    if ether is not None:
        record.src_mac = str(ether.src)
        record.dst_mac = str(ether.dst)
        record.has_link_layer = True

    ip = refs.get("ip")
    if ip is not None:
        record.src_ip = str(ip.src)
        record.dst_ip = str(ip.dst)
        record.ttl = int(ip.ttl) if ip.ttl is not None else None
        proto = int(ip.proto) if ip.proto is not None else -1
        record.protocol = IP_PROTOCOLS.get(proto, f"IP-{ip.proto}")
        if proto in (1, 58) and ip.type is not None:
            record.info = f"{record.protocol} type={ip.type} code={ip.code}"
    else:
        ipv6 = refs.get("ipv6")
        if ipv6 is not None:
            record.src_ip = str(ipv6.src)
            record.dst_ip = str(ipv6.dst)
            record.ttl = int(ipv6.hlim) if ipv6.hlim is not None else None
            record.protocol = str(ipv6.nh) if ipv6.nh is not None else "IPv6"
        else:
            arp = refs.get("arp")
            if arp is not None:
                record.src_ip = str(arp.psrc)
                record.dst_ip = str(arp.pdst)
                record.protocol = "ARP"
                record.info = f"ARP op={arp.op}"

    tcp = refs.get("tcp")
    if tcp is not None:
        record.transport = "TCP"
        record.src_port = int(tcp.sport)
        record.dst_port = int(tcp.dport)
        record.flags = str(tcp.flags)
    else:
        udp = refs.get("udp")
        if udp is not None:
            record.transport = "UDP"
            record.src_port = int(udp.sport)
            record.dst_port = int(udp.dport)

    if not record.protocol and record.transport:
        record.protocol = record.transport

    record.service = resolve_service(record.src_port, record.dst_port)

    if not record.info:
        record.info = _describe(refs, record.protocol)

    raw_layer = refs.get("raw")
    payload = b""
    if raw_layer is not None:
        try:
            payload = bytes(raw_layer.load)
        except Exception:
            payload = b""
    else:
        # No Raw layer means an application protocol was parsed into a layer of
        # its own (DNS is the common case). Its bytes are the payload, so surface
        # them -- otherwise a DNS query name is only visible as a field string
        # and is invisible to the hex view and to payload-scanning rules.
        #
        # Guard on the layer sitting above the transport header: without this,
        # a bare TCP SYN would report its own 20-byte header as "payload".
        innermost = record.layers[-1].name if record.layers else ""
        if innermost not in _PAYLOAD_EXCLUDED:
            try:
                payload = bytes(refs["innermost"])
            except Exception:
                payload = b""

    record.payload = payload[:MAX_PAYLOAD_STORE]
    record.payload_hex, record.payload_ascii = _payload_preview(payload)

    if keep_raw:
        try:
            record.raw = bytes(packet)
            if not record.length:
                record.length = len(record.raw)
        except Exception:
            record.raw = None

    return record
