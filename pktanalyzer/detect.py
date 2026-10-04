"""Anomaly detection over the decoded packet stream.

This is the part worth putting on a resume, because it is measurable: every
rule has a threshold you can tune, and a rule that cannot be evaluated against
labelled traffic is just a guess.

Each rule is a small class with an ``inspect`` method so rules stay
independent and individually testable. ``DetectionEngine`` runs them all and
returns ``Alert`` objects; nothing here imports tkinter.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque

from .models import Alert, PacketRecord

SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"

MAX_TRACKED_SOURCES = 5_000
ALERT_HISTORY = 500


class PortScanDetector:
    """Flags a source host that contacts many destination ports in one window.

    A normal client opens a handful of ports to a handful of hosts. A scanner
    sweeps ports, so the signal is *distinct destination ports per source*
    inside a short window, not raw volume.
    """

    rule_name = "port_scan"

    def __init__(self, threshold: int = 15, window: float = 5.0, cooldown: float = 20.0) -> None:
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        # source IP -> deque of (timestamp, destination port)
        self._probes: dict[str, deque[tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=2048)
        )
        self._last_alert: dict[str, float] = {}

    def inspect(self, record: PacketRecord) -> Alert | None:
        if not record.src_ip or record.dst_port is None:
            return None

        now = record.timestamp
        probes = self._probes[record.src_ip]
        probes.append((now, record.dst_port))

        cutoff = now - self.window
        while probes and probes[0][0] < cutoff:
            probes.popleft()

        distinct = len({port for _, port in probes})
        if distinct < self.threshold:
            return None

        previous = self._last_alert.get(record.src_ip)
        if previous is not None and now - previous < self.cooldown:
            return None
        self._last_alert[record.src_ip] = now

        targets = sorted({port for _, port in probes})
        return Alert(
            rule=self.rule_name,
            severity=SEVERITY_HIGH,
            timestamp=now,
            message=(
                f"{record.src_ip} probed {distinct} distinct ports on "
                f"{record.dst_ip or 'multiple hosts'} in {self.window:.0f}s "
                f"({', '.join(str(p) for p in targets[:8])}"
                f"{'...' if len(targets) > 8 else ''})"
            ),
        )

    def forget(self, source: str) -> None:
        self._probes.pop(source, None)


class SynFloodDetector:
    """Flags SYN packets not followed by an ACK, which is what a SYN flood is.

    Tracked as outstanding SYNs per destination rather than a raw SYN rate,
    because a busy TLS client legitimately sends many SYNs that *do* get ACKed.
    """

    rule_name = "syn_flood"

    def __init__(self, threshold: int = 100, window: float = 5.0, cooldown: float = 15.0) -> None:
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        self._pending: dict[tuple[str, str], deque[float]] = defaultdict(
            lambda: deque(maxlen=4096)
        )
        self._last_alert: dict[str, float] = {}

    def inspect(self, record: PacketRecord) -> Alert | None:
        if record.transport != "TCP" or not record.src_ip or not record.dst_ip:
            return None

        now = record.timestamp
        key = (record.src_ip, record.dst_ip)
        flags = record.flags.upper()

        if flags.startswith("R"):
            self._pending.pop(key, None)
            return None

        outstanding = self._pending[key]
        if "A" in flags:
            outstanding.clear()
            return None

        if not flags.startswith("S"):
            return None

        outstanding.append(now)
        cutoff = now - self.window
        while outstanding and outstanding[0] < cutoff:
            outstanding.popleft()

        if len(outstanding) < self.threshold:
            return None

        previous = self._last_alert.get(record.src_ip)
        if previous is not None and now - previous < self.cooldown:
            return None
        self._last_alert[record.src_ip] = now

        return Alert(
            rule=self.rule_name,
            severity=SEVERITY_MEDIUM,
            timestamp=now,
            message=(
                f"{len(outstanding)} unacknowledged SYNs from {record.src_ip} "
                f"to {record.dst_ip}:{record.dst_port} within {self.window:.0f}s"
            ),
        )


class PlaintextCredentialDetector:
    """Finds credentials sent unencrypted in payloads.

    Reports only the protocol and the location, never the secret itself --
    an analyzer that echoes passwords into a log is a liability.
    """

    rule_name = "plaintext_credentials"

    _HTTP_AUTH = re.compile(rb"(?i)\bauthorization\s*:\s*(basic|bearer)\b")
    _HTTP_PLAIN = re.compile(rb"(?i)\b(?:password|passwd|pwd)\s*[=:]\s*\S+")
    _FTP_AUTH = re.compile(rb"(?m)^(USER|PASS)\s+\S+", re.IGNORECASE)
    _TELNET = re.compile(rb"(?i)\b(telnet|login\s*:)\b")

    def __init__(self, cooldown: float = 30.0) -> None:
        self.cooldown = cooldown
        self._last_alert: dict[tuple[str, str], float] = {}

    def inspect(self, record: PacketRecord) -> Alert | None:
        # Inspect the payload, never the whole frame: ``record.raw`` also holds
        # binary link/network headers, which would defeat anchored patterns and
        # invite matches on header bytes.
        payload = record.payload
        # Only look where plaintext actually occurs; encrypted payloads would
        # match by coincidence and cost false positives.
        if not payload or record.service not in ("HTTP", "FTP", "TELNET", "POP3", "IMAP"):
            return None

        hit = None
        if record.service == "HTTP":
            if self._HTTP_AUTH.search(payload):
                hit = "HTTP Authorization header"
            elif self._HTTP_PLAIN.search(payload):
                hit = "HTTP credential parameter"
        elif record.service == "FTP":
            if self._FTP_AUTH.search(payload):
                hit = "FTP USER/PASS command"
        elif record.service == "TELNET" and self._TELNET.search(payload):
            hit = "Telnet prompt"
        elif record.service in ("POP3", "IMAP") and self._HTTP_PLAIN.search(payload):
            hit = f"{record.service} credential"

        if hit is None:
            return None

        key = (record.src_ip, hit)
        now = record.timestamp
        previous = self._last_alert.get(key)
        if previous is not None and now - previous < self.cooldown:
            return None
        self._last_alert[key] = now

        return Alert(
            rule=self.rule_name,
            severity=SEVERITY_HIGH,
            timestamp=now,
            message=(
                f"{hit} in cleartext {record.src_ip}:{record.src_port} -> "
                f"{record.dst_ip}:{record.dst_port}"
            ),
        )


class LargeTransferDetector:
    """Flags a single flow moving far more bytes than typical for its service."""

    rule_name = "large_transfer"

    def __init__(self, threshold_bytes: int = 8 * 1024 * 1024) -> None:
        self.threshold_bytes = threshold_bytes
        self._flow_bytes: dict[tuple[str, str, int | None, int | None], int] = defaultdict(int)
        self._reported: set[tuple[str, str, int | None, int | None]] = set()

    def inspect(self, record: PacketRecord) -> Alert | None:
        if not record.src_ip or not record.dst_ip:
            return None
        key = (record.src_ip, record.dst_ip, record.src_port, record.dst_port)
        self._flow_bytes[key] += record.length

        if self._flow_bytes[key] < self.threshold_bytes or key in self._reported:
            return None
        self._reported.add(key)

        return Alert(
            rule=self.rule_name,
            severity=SEVERITY_LOW,
            timestamp=record.timestamp,
            message=(
                f"flow {record.src_ip}:{record.src_port} -> "
                f"{record.dst_ip}:{record.dst_port} passed "
                f"{self._flow_bytes[key] / 1024 / 1024:.1f} MB"
            ),
        )


class DetectionEngine:
    """Runs every rule over the stream and keeps a bounded alert history."""

    def __init__(self, rules: list | None = None) -> None:
        self.rules = rules if rules is not None else [
            PortScanDetector(),
            SynFloodDetector(),
            PlaintextCredentialDetector(),
            LargeTransferDetector(),
        ]
        self._history: deque[Alert] = deque(maxlen=ALERT_HISTORY)
        self.total_alerts = 0

    def inspect(self, record: PacketRecord) -> list[Alert]:
        """Return alerts raised by this packet. A broken rule cannot stop the rest."""
        alerts: list[Alert] = []
        for rule in self.rules:
            try:
                alert = rule.inspect(record)
            except Exception:
                continue
            if alert is not None:
                alerts.append(alert)
                self._history.append(alert)
                self.total_alerts += 1
        return alerts

    def inspect_many(self, records: list[PacketRecord]) -> list[Alert]:
        found: list[Alert] = []
        for record in records:
            found.extend(self.inspect(record))
        return found

    @property
    def history(self) -> list[Alert]:
        return list(self._history)

    def reset(self) -> None:
        self._history.clear()
        self.total_alerts = 0
        for rule in self.rules:
            if hasattr(rule, "cooldown"):
                rule._last_alert.clear()
            if hasattr(rule, "_probes"):
                rule._probes.clear()
            if hasattr(rule, "_pending"):
                rule._pending.clear()
            if hasattr(rule, "_flow_bytes"):
                rule._flow_bytes.clear()
                rule._reported.clear()


def measure_accuracy(
    positives: list[PacketRecord],
    negatives: list[PacketRecord],
    rule_factory=PortScanDetector,
) -> dict[str, float]:
    """Score a rule against labelled traffic.

    Returns precision, recall and F1 so a detection claim in a README can be
    backed by a number instead of a vibe.

    Cooldowns are disabled while scoring. A cooldown is a notification-rate
    limiter, not part of the detection decision: leaving it on would mark every
    packet after the first alert as a false negative and make a working rule
    look like it had ~0 recall. Detection windows and thresholds stay active,
    because those *are* the decision.
    """
    rule = rule_factory()
    if hasattr(rule, "cooldown"):
        rule.cooldown = 0.0

    true_positives = sum(1 for p in positives if rule.inspect(p) is not None)
    false_positives = sum(1 for n in negatives if rule.inspect(n) is not None)
    false_negatives = len(positives) - true_positives

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }
