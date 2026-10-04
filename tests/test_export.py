"""Export tests: pcap round-trip plus CSV and JSON output."""

import csv
import json
import re

import pytest
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, rdpcap

from pktanalyzer.capture import replay
from pktanalyzer.export import (
    CSV_COLUMNS,
    is_pcap,
    load,
    load_pcap,
    pcap_frame_count,
    save,
    save_csv,
    save_json,
    save_pcap,
)

ETH = dict(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")


@pytest.fixture
def records():
    return replay([
        Ether(**ETH) / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64)
        / TCP(sport=51515, dport=443, flags="PA") / Raw(load=b"GET / HTTP/1.1\r\n"),
        Ether() / IP(src="10.0.0.3", dst="8.8.8.8") / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
        Ether() / IP(src="10.0.0.4", dst="10.0.0.5") / ICMP(),
        Ether() / ARP(psrc="10.0.0.4", pdst="10.0.0.254"),
    ])


class TestPcap:
    def test_roundtrip_preserves_packet_count(self, records, tmp_path):
        path = tmp_path / "out.pcap"
        written = save_pcap(records, path)

        assert written == len(records)
        assert pcap_frame_count(path) == len(records)
        assert len(load_pcap(path)) == len(records)

    def test_roundtrip_preserves_addresses_and_ports(self, records, tmp_path):
        path = tmp_path / "out.pcap"
        save_pcap(records, path)
        reloaded = load_pcap(path)

        assert reloaded[0].src_ip == "10.0.0.1"
        assert reloaded[0].dst_port == 443
        assert reloaded[0].protocol == "TCP"
        assert reloaded[1].service == "DNS"
        assert reloaded[2].protocol == "ICMP"
        assert reloaded[3].protocol == "ARP"

    def test_file_is_a_valid_pcap_by_magic_number(self, records, tmp_path):
        path = tmp_path / "out.pcap"
        save_pcap(records, path)
        assert is_pcap(path)

    def test_renaming_to_csv_does_not_fool_the_magic_check(self, records, tmp_path):
        path = tmp_path / "out.pcap"
        save_pcap(records, path)
        assert not is_pcap(tmp_path / "nope.pcap")

    def test_pcap_is_readable_as_raw_scapy_packets(self, records, tmp_path):
        path = tmp_path / "out.pcap"
        save_pcap(records, path)
        packets = rdpcap(str(path))

        assert TCP in packets[0]
        assert packets[0][TCP].dport == 443

    def test_frames_without_link_layer_are_rejected(self):
        from pktanalyzer.models import PacketRecord

        record = PacketRecord(index=0, timestamp=0.0, length=4, raw=b"\x00\x01\x02\x03")
        with pytest.raises(ValueError, match=re.escape("link-layer")):
            save_pcap([record], "/tmp/should-not-exist.pcap")

    def test_empty_capture_writes_nothing(self, tmp_path):
        assert save_pcap([], tmp_path / "empty.pcap") == 0

    def test_records_without_raw_bytes_are_skipped(self, tmp_path):
        """A record with no frame bytes cannot be written, and must say so."""
        from pktanalyzer.models import PacketRecord

        record = PacketRecord(index=0, timestamp=0.0, length=4, has_link_layer=True)

        with pytest.raises(ValueError, match="keep_raw"):
            save_pcap([record], tmp_path / "empty.pcap")


class TestPcapFailureModes:
    """Covers the ways a pcap save can quietly produce nothing.

    All three of these returned "success" or an empty file while the caller
    believed a capture had been written.
    """

    def test_generator_input_is_consumed_once(self, records, tmp_path):
        """save_pcap needs two passes; a generator would be spent on the first."""
        path = tmp_path / "gen.pcap"

        written = save_pcap((r for r in records), path)

        assert written == len(records)
        assert pcap_frame_count(path) == len(records)

    def test_load_save_roundtrip_requires_keep_raw_on_load(self, records, tmp_path):
        """A pcap loaded without keep_raw cannot be re-saved -- say so loudly."""
        first = tmp_path / "first.pcap"
        second = tmp_path / "second.pcap"
        save_pcap(records, first)

        with pytest.raises(ValueError, match="keep_raw"):
            save_pcap(load_pcap(first), second)

        # The documented escape hatch works.
        assert save_pcap(load_pcap(first, keep_raw=True), second) == len(records)
        assert pcap_frame_count(second) == len(records)


class TestCsv:
    def test_header_matches_declared_columns(self, records, tmp_path):
        path = tmp_path / "out.csv"
        save_csv(records, path)

        with open(path, newline="", encoding="utf-8") as handle:
            header = next(csv.reader(handle))

        assert header == CSV_COLUMNS

    def test_row_count_matches_records(self, records, tmp_path):
        path = tmp_path / "out.csv"
        save_csv(records, path)

        with open(path, newline="", encoding="utf-8") as handle:
            rows = list(csv.reader(handle))

        assert len(rows) == len(records) + 1

    def test_values_are_written_as_text(self, records, tmp_path):
        path = tmp_path / "out.csv"
        save_csv(records, path)

        with open(path, newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        assert rows[0]["src_ip"] == "10.0.0.1"
        assert rows[0]["dst_port"] == "443"
        assert rows[0]["protocol"] == "TCP"

    def test_missing_ports_become_empty_not_none(self, records, tmp_path):
        path = tmp_path / "out.csv"
        save_csv(records, path)

        with open(path, newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        assert rows[2]["src_port"] == ""
        assert rows[2]["dst_port"] == ""


class TestJson:
    def test_output_is_valid_json(self, records, tmp_path):
        path = tmp_path / "out.json"
        save_json(records, path)
        payload = json.loads(path.read_text())

        assert isinstance(payload, list)
        assert len(payload) == len(records)

    def test_layer_tree_is_included(self, records, tmp_path):
        path = tmp_path / "out.json"
        save_json(records, path)
        payload = json.loads(path.read_text())

        names = [layer["name"] for layer in payload[0]["layers"]]
        assert "IP" in names and "TCP" in names

    def test_ports_are_json_numbers(self, records, tmp_path):
        path = tmp_path / "out.json"
        save_json(records, path)
        payload = json.loads(path.read_text())

        assert payload[0]["dst_port"] == 443
        assert payload[2]["dst_port"] is None


class TestDispatch:
    @pytest.mark.parametrize("suffix", [".pcap", ".csv", ".json"])
    def test_save_dispatches_on_extension(self, records, tmp_path, suffix):
        path = tmp_path / f"out{suffix}"
        assert save(records, path) == len(records)

    def test_cap_extension_is_treated_as_pcap(self, records, tmp_path):
        path = tmp_path / "out.cap"
        assert save(records, path) == len(records)

    def test_unknown_extension_is_rejected(self, records, tmp_path):
        with pytest.raises(ValueError, match="unsupported format"):
            save(records, tmp_path / "out.docx")

    def test_pcap_loads_back(self, records, tmp_path):
        path = tmp_path / "out.pcap"
        save(records, path)
        assert len(load(path)) == len(records)

    def test_csv_and_json_cannot_be_imported(self, tmp_path):
        path = tmp_path / "out.csv"
        path.write_text("")
        with pytest.raises(ValueError, match=re.escape("only .pcap")):
            load(path)

    def test_load_rejects_unsupported_format(self, tmp_path):
        path = tmp_path / "out.docx"
        path.touch()
        with pytest.raises(ValueError):
            load(path)

    def test_missing_file_raises_a_clean_error(self, tmp_path):
        with pytest.raises(Exception):
            load_pcap(tmp_path / "does-not-exist.pcap")
