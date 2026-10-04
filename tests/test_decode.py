import pytest
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

from pktanalyzer.decode import decode, service_for
from pktanalyzer.models import PacketRecord


@pytest.fixture
def ethernet():
    return Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")


def layer_names(record: PacketRecord) -> list[str]:
    return [layer.name for layer in record.layers]


class TestTransportDecoding:
    def test_tcp_fields_are_extracted(self, ethernet):
        packet = ethernet / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64) / TCP(
            sport=51515, dport=443, flags="PA"
        )
        record = decode(packet, index=1)

        assert record.src_mac == "aa:bb:cc:dd:ee:01"
        assert record.dst_mac == "aa:bb:cc:dd:ee:02"
        assert record.src_ip == "10.0.0.1"
        assert record.dst_ip == "10.0.0.2"
        assert record.src_port == 51515
        assert record.dst_port == 443
        assert record.transport == "TCP"
        assert record.protocol == "TCP"
        assert record.ttl == 64
        assert record.service == "HTTPS"
        assert record.flags == "PA"
        assert record.index == 1

    def test_udp_fields_are_extracted(self, ethernet):
        packet = ethernet / IP(src="8.8.8.8", dst="10.0.0.2") / UDP(sport=53, dport=41234)
        record = decode(packet)

        assert record.transport == "UDP"
        assert record.src_port == 53
        assert record.dst_port == 41234
        assert record.service == "DNS"

    def test_table_row_is_aligned_with_declared_columns(self, ethernet):
        packet = ethernet / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=80)
        row = decode(packet).table_row()

        assert len(row) == 11
        assert row[2] == "TCP"
        assert row[3] == "1.1.1.1"


class TestProtocolsTheOriginalVersionDropped:
    """The old code only understood TCP/UDP. Everything here is new coverage."""

    def test_icmp_packets_are_decoded(self, ethernet):
        record = decode(ethernet / IP(src="10.0.0.5", dst="10.0.0.6") / ICMP(type=8))

        assert record.protocol == "ICMP"
        assert "type=8" in record.info
        assert record.src_port is None

    def test_arp_packets_are_decoded(self, ethernet):
        record = decode(ethernet / ARP(psrc="192.168.1.5", pdst="192.168.1.1", op=1))

        assert record.protocol == "ARP"
        assert record.src_ip == "192.168.1.5"
        assert record.dst_ip == "192.168.1.1"

    def test_dns_layers_are_walked_recursively(self, ethernet):
        record = decode(
            ethernet
            / IP(src="10.0.0.9", dst="8.8.8.8")
            / UDP(dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com"))
        )

        assert "DNS" in layer_names(record)
        assert record.service == "DNS"

    def test_dns_query_name_is_readable_not_byte_stringified(self, ethernet):
        """scapy nests DNSQR in a list field; naive str() hides the qname."""
        record = decode(
            ethernet / IP() / UDP(dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com"))
        )
        dns_layer = next(layer for layer in record.layers if layer.name == "DNS")

        assert "example.com" in dns_layer.fields["qd"]
        assert "b'example.com" not in dns_layer.fields["qd"]

    def test_every_layer_is_reported_not_just_known_ones(self, ethernet):
        record = decode(ethernet / IP() / TCP() / Raw(load=b"hello"))

        assert layer_names(record) == ["Ether", "IP", "TCP", "Raw"]


class TestPayloadHandling:
    def test_payload_is_previewed_as_hex_and_ascii(self, ethernet):
        record = decode(ethernet / IP() / TCP() / Raw(load=b"GET / HTTP/1.1"))

        assert "47 45 54" in record.payload_hex
        assert "GET / HTTP/1.1" in record.payload_ascii

    def test_payload_preview_is_bounded(self, ethernet):
        record = decode(ethernet / IP() / TCP() / Raw(load=b"A" * 4096))

        assert len(record.payload_hex) < 512
        assert len(record.payload_ascii) <= 64

    def test_binary_payload_does_not_crash_ascii_preview(self, ethernet):
        record = decode(ethernet / IP() / UDP() / Raw(load=bytes(range(32))))

        assert "\x00" not in record.payload_ascii
        assert record.payload_ascii.count(".") > 0

    def test_packet_without_payload_has_empty_preview(self, ethernet):
        record = decode(ethernet / IP() / UDP())
        assert record.payload_hex == ""


class TestRobustness:
    def test_truncated_tcp_header_does_not_raise(self):
        record = decode(Ether() / IP(src="1.1.1.1") / bytes(TCP())[:8])

        assert isinstance(record, PacketRecord)

    def test_random_bytes_are_handled(self):
        record = decode(Ether(bytes(60)))

        assert isinstance(record, PacketRecord)

    def test_empty_packet_is_handled(self):
        record = decode(Raw(b""))
        assert isinstance(record, PacketRecord)

    def test_large_field_values_are_truncated_for_display(self, ethernet):
        from pktanalyzer.decode import MAX_FIELD_CHARS

        noisy = b"P" * 500
        record = decode(ethernet / IP(options=[noisy]) / TCP())

        limit = MAX_FIELD_CHARS + len("...")
        assert all(len(v) <= limit for layer in record.layers for v in layer.fields.values())


class TestLengthAndRetention:
    """Guards the two things that silently break the performance work.

    Both bugs here were invisible: a zero length disables every size-based
    rule, and a NameError inside the keep_raw branch was swallowed by its own
    except clause, quietly producing records that could not be exported.
    """

    def test_synthetic_packets_still_get_a_length(self, ethernet):
        """wirelen is unset on built frames; length must not be left at 0."""
        record = decode(ethernet / IP(src="1.1.1.1") / TCP(dport=80) / Raw(load=b"x" * 40))

        assert record.length > 40

    def test_captured_wirelen_is_preferred(self, ethernet):
        packet = ethernet / IP() / TCP(dport=80)
        packet.wirelen = 1514

        assert decode(packet).length == 1514

    def test_keep_raw_true_retains_a_serialisable_frame(self, ethernet):
        packet = ethernet / IP(src="1.1.1.1") / TCP(dport=80) / Raw(load=b"hello")

        record = decode(packet, keep_raw=True)

        assert record.raw is not None, "keep_raw=True must populate raw"
        assert bytes(packet) in record.raw

    def test_keep_raw_false_skips_serialisation(self, ethernet):
        record = decode(ethernet / IP() / TCP(dport=80), keep_raw=False)
        assert record.raw is None

    def test_keep_raw_is_independent_of_length(self, ethernet):
        packet = ethernet / IP() / TCP(dport=80)
        packet.wirelen = 1514

        assert decode(packet, keep_raw=True).length == 1514

    def test_link_layer_flag_is_recorded(self):
        assert decode(Ether() / IP()).has_link_layer is True

    def test_link_layer_flag_absent_for_bare_ip(self):
        assert decode(IP(src="1.1.1.1") / TCP()).has_link_layer is False


class TestWireBytesDissection:
    """Reproduces how scapy actually hands packets to a sniffer.

    A sniffer receives *bytes off a socket*, not a built packet graph, so the
    layer chain comes from scapy re-parsing those bytes and applying its port
    bindings. Building `UDP(dport=53)/DNS(...)` in a test would prove nothing --
    it hardcodes the answer. These tests re-parse from bytes so they fail if a
    capability is only real for synthetic packets.
    """

    @staticmethod
    def _from_wire(packet) -> PacketRecord:
        return decode(Ether(bytes(packet)))

    def test_dns_query_is_dissected_from_raw_bytes(self):
        """DNS is port-bound by scapy, so real queries decode into fields."""
        frame = (
            Ether()
            / IP(src="10.0.0.1", dst="8.8.8.8")
            / UDP(sport=40000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com"))
        )

        record = self._from_wire(frame)

        assert "DNS" in layer_names(record)
        assert record.service == "DNS"
        assert record.protocol == "UDP"

        # Payload extraction must reach DNS bytes, not just the Raw layer, or the
        # query name is invisible to the hex view and to payload-scanning rules.
        assert record.payload, "DNS payload bytes were dropped"
        dns_fields = record.layers[-1].fields
        assert "qname=example.com" in " ".join(dns_fields.values())

        # DNS wire format is length-prefixed labels (\x07example\x03com\x00), so
        # the readable view substitutes non-printables with dots.
        assert "example" in record.payload_ascii
        assert "com" in record.payload_ascii

    def test_mdns_is_dissected_from_raw_bytes(self):
        frame = (
            Ether()
            / IP(src="10.0.0.1", dst="224.0.0.251")
            / UDP(sport=5353, dport=5353)
            / DNS(rd=1, qd=DNSQR(qname="printer.local"))
        )

        assert "DNS" in layer_names(self._from_wire(frame))

    @pytest.mark.parametrize(
        ("label", "packet"),
        [
            ("http", Ether() / IP() / TCP(dport=80) / Raw(load=b"GET / HTTP/1.1\r\n\r\n")),
            ("tls", Ether() / IP() / TCP(dport=443) / Raw(load=bytes(range(80)))),
            ("ssh", Ether() / IP() / TCP(dport=22) / Raw(load=b"SSH-2.0-x\r\n")),
        ],
    )
    def test_unbound_application_protocols_stay_opaque(self, label, packet):
        """Documents the real limit rather than pretending these are parsed.

        scapy has no port binding that turns these bytes into HTTP/TLS/SSH
        layers, so they surface as Raw. The payload is still bounded and
        printable, which is what the detail view relies on.
        """
        record = self._from_wire(packet)

        assert "Raw" in layer_names(record)
        assert not any(
            name in layer_names(record) for name in ("HTTP", "TLS", "SSH", "SSLv3")
        ), f"{label} unexpectedly parsed into fields"
        assert len(record.payload) <= 2048

    def test_tcp_only_frame_has_no_raw_layer(self):
        """A bare SYN carries no application payload at all."""
        record = self._from_wire(Ether() / IP() / TCP(dport=80))

        assert record.payload == b""
        assert record.length == 54  # minimum Ethernet frame, not a synthetic 0
        assert layer_names(record) == ["Ether", "IP", "TCP"]


class TestServiceResolution:
    @pytest.mark.parametrize("port,expected", [
        (80, "HTTP"), (443, "HTTPS"), (22, "SSH"), (3389, "RDP"), (None, ""),
    ])
    def test_known_services(self, port, expected):
        assert service_for(port) == expected

    def test_unknown_high_port_falls_back(self):
        assert service_for(65000).startswith(("PORT-", "dport-", "hp-", "unknown"))

    def test_packet_survives_pcap_roundtrip(self, tmp_path, ethernet):
        packets = [
            ethernet / IP() / TCP(dport=80) / Raw(load=b"x"),
            ethernet / IP() / UDP(dport=53),
        ]
        path = tmp_path / "sample.pcap"
        wrpcap(str(path), packets)

        from scapy.all import rdpcap
        for index, packet in enumerate(rdpcap(str(path))):
            assert isinstance(decode(packet, index), PacketRecord)
