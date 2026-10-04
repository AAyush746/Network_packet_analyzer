# pktanalyzer

A live network packet analyzer built on [scapy](https://scapy.net): recursive
protocol dissection, rolling traffic statistics, anomaly detection, and pcap
import/export behind a Tkinter GUI.

```
sudo python main.py                 # live capture (needs CAP_NET_RAW)
python main.py --demo               # run on synthetic traffic, no privileges
python -m pytest                    # 167 tests
python bench.py --packets 20000     # reproduce the numbers below
```

```

---

## What it does

| Area | Detail |
|---|---|
| **Dissection** | Walks scapy's payload chain, so every layer present in the frame is decoded — not a hardcoded TCP/UDP list |
| **Layers decoded** | Ethernet, IPv4, IPv6, ARP, ICMP, ICMPv6, TCP, UDP, DNS/mDNS, plus any other registered scapy layer. HTTP, TLS, DHCP and SSH payloads are **not** parsed into fields — they are shown as hex/ASCII (see [Limitations](#limitations)) |
| **Service labelling** | 30+ well-known ports plus IANA fallback, resolved across **both** ports of a flow |
| **Statistics** | Rolling packets/sec and bytes/sec, per-protocol mix, top talkers, top ports, unique hosts, average frame size |
| **Detection** | Port scan, SYN flood, plaintext credentials, oversized flow — each with tunable thresholds |
| **Capture** | Interface discovery, BPF filter validation, live start/stop, bounded queue with drop accounting |
| **Persistence** | pcap read/write, CSV and JSON export |
| **UI** | Sortable columns, protocol + text filtering, packet detail tree, colour-coded alert panel, live counters |

---

## Architecture

The one rule that shapes the whole codebase: **the analysis pipeline contains no
UI imports.**

```
capture.py   thread ──┐
                      ├─► queue ──► Tk main thread ──► treeview
decode.py  ──────────┤   (drain)      └─► detail view
stats.py            │
detect.py  ─────────┘
        │
        └──► export.py ──► pcap / csv / json
```

```
pktanalyzer/
├── models.py     PacketRecord, LayerInfo, Alert   (no behaviour, just shape)
├── decode.py     payload-chain walk, field rendering, service resolution
├── capture.py    interface discovery, sniffer thread, queue bridge
├── stats.py      O(1) rolling counters
├── detect.py     one class per rule + accuracy scoring
├── export.py     pcap / csv / json
└── ui/app.py     widgets only
```

Because `decode`, `stats` and `detect` are headless, the entire pipeline is
testable without a display or a network interface — which is what the 167 tests
exercise.

### Why the queue

The first version of this project called `root.after()` from inside the sniffing
thread. Tkinter is single-threaded; that is undefined behaviour and it
intermittently hung. Now the capture thread does exactly one thing — decode a
frame and `put_nowait` onto a `queue.Queue` — and the Tk thread drains it on an
`after()` timer. Analysis (regex, counters) also runs on the worker thread, so
the UI thread only inserts widgets.

The batch cap in `drain()` matters as much as the queue: draining 50,000 rows in
one call would freeze the window for seconds, so it returns at most 500 and
reschedules.

---

## Measured performance

Reproduce with `python bench.py --packets 20000`. Numbers from Python 3.14.6,
single core, synthetic mixed traffic (55% TCP, 25% DNS, 10% ICMP, 7% ARP, 3%
scan).

| Metric | Value |
|---|---|
| Decode throughput | **8,200 packets/sec** (median of 6 passes; spread ±2.5%) |
| Mean latency | 121 µs/packet |
| p50 / p95 / p99 | 50.6 / 322.5 / 441.8 µs |
| Decode + stats + detection | **7,191 packets/sec** (139 µs/packet) |
| Memory per record | **108 bytes** (2.1 MB for 20,000 records) |
| Port-scan precision / recall / F1 | **1.000 / 0.953 / 0.976** |
| Tests / coverage | 167 tests / 86% |

Two numbers are deliberately quoted conservatively:

* **Throughput is a median of repeated passes, not a best case.** Single runs on
  this machine varied between 7,900 and 10,400 packets/sec. Quoting the 10,400
  would have been a number no reviewer could reproduce.
* **Latency percentiles are bimodal.** See the GC note below.

### The optimisation that mattered

The first working version decoded at **1,107 packets/sec**. Profiling found two
causes, neither obvious:

1. **`Packet.__len__` is `len(bytes(self))`.** A length fallback written as
   "cheap" was actually a full frame serialisation — ~0.5 ms, the entire decode
   budget. Captured frames always carry `wirelen`, so the fallback now only
   fires for synthetic packets, and `bench.py` stamps `wirelen` to model a real
   interface.
2. **`socket.getservbyport` on every packet.** A syscall per unknown port,
   producing a 180 ms first-packet outlier. Ports repeat constantly, so it is
   now a dict lookup.

Together: **1,107 → 8,200 packets/sec (7.4×)**, verified by re-running the
benchmark rather than by arithmetic on the two results.

### Honest trade-offs

* **Frame retention costs 4.5×.** `keep_raw=True` serialises every frame so the
  capture can be exported to pcap: 541 µs/packet vs 121 µs. It is on by default
  because export is a feature, and `CaptureEngine(keep_raw=False)` disables it.
* **Cyclic GC produces the latency tail, not decoding.** A `PacketRecord` owns a
  list of `LayerInfo` plus a dict per layer, so every packet contributes several
  GC-tracked containers. Retaining tens of thousands of them makes collection
  passes expensive. Measured across repeated passes, the *median* packet is
  unaffected (0.2 µs) but individual packets pay **25–60 ms** pauses — which is
  what a UI thread would experience as a freeze. `gc.freeze()` after startup
  removes the pre-warmed outlier but does not remove the steady-state cost;
  disabling the cyclic collector entirely is unsafe because scapy packet objects
  do form reference cycles.
* **A DNS fix cost ~20% throughput, deliberately.** Payload extraction originally
  only read the `Raw` layer, so a dissected DNS query had *no* payload: its name
  was visible as a field string but invisible to the hex view and to the
  payload-scanning detection rules. The fix falls back to the innermost layer
  when that layer sits above the transport header — and `_dissect()` records it
  during the walk it already performs, rather than re-traversing the chain. DNS
  query names are now inspectable; bare SYN/UDP/ARP/ICMP frames correctly report
  zero payload bytes.
* **Throughput is decode-bound, not capture-bound.** Reading frames from a kernel
  socket is not measured here, so end-to-end capture rate will be lower.

### Detection accuracy

Precision/recall are measured, not asserted — `detect.measure_accuracy()` scores
a rule against labelled traffic, and `bench.py` prints the result:

```
precision 1.0 | recall 0.953 | f1 0.976
TP 286 | FP 0 | FN 14
```

Recall is capped below 1.0 by design: a window-based rule needs `threshold`
packets of evidence before it can fire, so the first `threshold - 1` packets of
any scan are unavoidable misses. `tests/test_detect.py` asserts that exact
ceiling rather than an impossible zero false negatives.

The `SYN flood` rule tracks *outstanding* SYNs per destination rather than a raw
SYN rate, because a busy TLS client legitimately emits many SYNs that get
answered. The plaintext credential rule inspects `record.payload` and never
`record.raw` — scanning whole frames lets anchored patterns match binary header
bytes — and **never includes the secret in its own alert text**.

---

## Development

```bash
pip install -r requirements.txt

pytest                       # 167 tests
pytest --cov=pktanalyzer     # coverage report
ruff check .                 # lint
python bench.py --packets 50000
```

`bench.py` needs no capture privileges: it replays synthetic frames through the
real decode, statistics and detection code, so benchmark numbers are
reproducible on any machine.

### Testing approach

`capture.py` tests mock scapy's `sniff` rather than opening a raw socket —
CI runners have no `CAP_NET_RAW`, so a suite requiring root would never execute.
The threading contract, queue overflow accounting and error paths are still
covered. GUI tests skip automatically when Tk cannot open a display.

Each fix during development came from a failing test, including several real bugs
this rewrite introduced: a name collision that wrote capture errors to the
statistics object, a queue that returned alert tuples where callers expected
`Alert` objects, one failing rule discarding already-decoded packets, and tree
item ids derived from packet indexes that collided on replay.

---

## Requirements

* Python 3.11+
* `scapy >= 2.5`
* Linux/macOS: `sudo` or `CAP_NET_RAW` for live capture. Windows: install
  [Npcap](https://npcap.com/) in WinPcap-compatible mode.
* Tkinter is part of the standard distribution on Linux (`python3-tk`) and
  macOS python.org builds; it is not bundled on Windows.

---

## Limitations

* **HTTP, TLS, DHCP and SSH payloads are not parsed into fields.** scapy only
  auto-binds a handful of application protocols to their ports — DNS and mDNS
  are among them, which is why DNS queries are dissected but a TLS ClientHello
  is not. Those payloads still appear as bounded hex + printable-ASCII. Adding
  them means either importing `scapy.layers.http` / `scapy.layers.tls` and
  calling `bind_layers` at import time, or writing an application-layer decoder.
* **IPv6 is parsed but not analysed.** Fields are extracted; there are no v6
  specific detection rules.
* **Single interface at a time**, with no merging across interfaces.
* **Detection thresholds are uncalibrated against real-world datasets.** The
  accuracy figures above use synthetic traffic. Validating against labelled
  pcaps (CICIDS2017, MAWI) is the obvious next step and the one piece of work
  that would most improve the headline claims.
* **Detection runs in-process**, so a rule that loops would stall capture. The
  rules here are counter- and regex-bounded, but there is no per-rule timeout.
* **Throughput is measured for the analysis pipeline only.** Frame *acquisition*
  from the kernel socket is not included, so end-to-end capture rate will be
  lower than the figures above.

## Licence

MIT