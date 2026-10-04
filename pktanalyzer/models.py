"""Data structures passed between the capture engine, analyzers and the UI.

Every field is optional/typed so the UI can render a partial record while a
packet is still being decoded. Nothing here imports tkinter, which keeps the
whole analysis pipeline unit-testable without a display.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

MAX_PAYLOAD_PREVIEW = 64
# Full payload kept for content inspection (detection rules, hex view). Bounded
# so a capture of large transfers cannot grow without limit.
MAX_PAYLOAD_STORE = 2048


@dataclass(frozen=True, slots=True)
class LayerInfo:
    """One protocol layer inside a packet, e.g. IPv4 or TCP."""

    name: str
    fields: dict[str, str] = field(default_factory=dict)

    def summary(self) -> str:
        if not self.fields:
            return self.name
        joined = "  ".join(f"{k}={v}" for k, v in self.fields.items())
        return f"{self.name}: {joined}"


@dataclass(slots=True)
class PacketRecord:
    """A decoded packet. Column indices are consumed by the UI table."""

    index: int
    timestamp: float
    length: int

    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None

    protocol: str = ""
    transport: str = ""
    service: str = ""
    ttl: int | None = None
    flags: str = ""
    info: str = ""

    layers: list[LayerInfo] = field(default_factory=list)
    has_link_layer: bool = False
    payload: bytes = field(default=b"", repr=False, compare=False)
    payload_hex: str = ""
    payload_ascii: str = ""
    raw: bytes | None = field(default=None, repr=False, compare=False)

    def table_row(self) -> tuple[str, ...]:
        """Flat tuple for ttk.Treeview, in the order the UI declares columns."""
        return (
            str(self.index),
            time.strftime("%H:%M:%S", time.localtime(self.timestamp)),
            self.protocol,
            self.src_ip or self.src_mac,
            self.src_port if self.src_port is not None else "",
            self.dst_ip or self.dst_mac,
            self.dst_port if self.dst_port is not None else "",
            self.service,
            str(self.ttl) if self.ttl is not None else "",
            str(self.length),
            self.info,
        )


@dataclass(frozen=True, slots=True)
class Alert:
    """A finding raised by the detection engine."""

    rule: str
    severity: str
    message: str
    timestamp: float

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.rule}: {self.message}"
