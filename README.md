# iotbreach
![tests](https://github.com/5h4d0wn1k/iotbreach/actions/workflows/ci.yml/badge.svg) ![MIT](https://img.shields.io/badge/license-MIT-blue.svg)

IoT/SCADA/embedded offensive security framework — MQTT/CoAP/UPnP/Modbus/CAN/BLE/Zigbee/433, firmware extraction+audit, fuzzing, ICS/SCADA kill-chain simulation.

> **WARNING**: Offensive security tooling. Authorized testing / education ONLY. Targets must be localhost sims or your own lab.

## IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

### Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

### Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

### Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

### Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

### No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

### Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

## RF regulatory note

ioTBREACH simulates Zigbee and 433 MHz protocols **as bytes only** (fixtures, in-memory
packets). It contains **no live radio transmission capability**. Always check your local
ISM-band regulations before any real-world testing; this software never transmits.

---

## Quickstart

```bash
python3 -m pip install -e .
python3 -m iotbreach --help
python3 -m iotbreach --demo        # offline full demo, exit 0
python3 -m unittest discover -s tests
```

Requires Python ≥ 3.9 and `pyyaml`. No real hardware needed — all protocols are
proven offline against built-in simulated buses/servers on localhost sockets
(MQTT/CoAP/Modbus), fixture frames (CAN/BLE/Zigbee/433), and a UART-style byte
harness.

## Commands overview

| Command | Purpose |
|---|---|
| `mqtt` | MQTT 3.1.1 packet build/parse + broker sim; unauth subscribe topic leak |
| `coap` | CoAP (RFC 7252) build/parse + UDP sim; firmware-update tamper accepted |
| `upnp` | SSDP discovery + HNAP SOAP command-injection proof on localhost spoofer |
| `modbus` | Modbus-TCP build/parse (FC1–FC5) + no-auth slave sim; write coil → temp control |
| `firmware` | binwalk-style signature/ents grep, squashfs-lite/ELF headers, entropy map, embedded config grep |
| `fwud` | firmware audit: version parse, offline CVE table, hash verify, tamper detect |
| `can` | CAN build/parse, bus sim, OBD-II PIDs, replay detection, DoS fault counter |
| `ble` | BLE ADV + GATT ATT build/parse (CRC-24); smart-lock spoof open |
| `zigbee-433` | ZLL beacon parse, 433 MHz OOK packetcraft, replay detect |
| `fuzz` | protocol fuzzer (mutate fixtures → localhost sims → anomaly capture) |
| `attack` | full ICS/SCADA kill-chain sim (recon → read → write → confirm) |
| `parse` | parse raw hex packets (MQTT/CoAP/Modbus) |
| `--demo` | run everything on localhost, exit 0 on success |

## Usage examples

```bash
# MQTT: start broker sim, subscribe, see topics leak without auth
python3 -m iotbreach mqtt broker-start
python3 -m iotbreach mqtt subscribe --topic '#' --leak

# Modbus: start slave, read holding registers, write coil (heater ON)
python3 -m iotbreach modbus sim-start
python3 -m iotbreach modbus read --fc 3 --addr 0 --qty 4
python3 -m iotbreach modbus write-coil --addr 0 --value 1

# CoAP: start sim, discover resources, tamper the firmware updater endpoint
python3 -m iotbreach coap sim-start
python3 -m iotbreach coap get --path .well-known/core --port 15683
python3 -m iotbreach coap firmware-tamper --port 15683

# UPnP: SSDP discover + HNAP command injection on the spoofer
python3 -m iotbreach upnp hnap-inject --port 11900

# CAN: replay attack detection, DoS fault counter
python3 -m iotbreach can replay --count 10 --port 17000
python3 -m iotbreach can dos --frames 300 --port 17000

# BLE: read battery, read lock, spoof unlock
python3 -m iotbreach ble spoof-unlock --port 17001

# Firmware
python3 -m iotbreach firmware extract --image iotbreach/fixtures/firmware_v1.bin
python3 -m iotbreach firmware audit --image iotbreach/fixtures/firmware_v1.bin
python3 -m iotbreach fwud audit --image iotbreach/fixtures/firmware_v1.bin   # fwud = firmware alias

# Fuzz a protocol
python3 -m iotbreach fuzz run --protocol modbus --port 15050 --iterations 200

# Kill chain (dry-run default; destructive write requires explicit opt-out)
python3 -m iotbreach attack run --dry-run --mqtt-port 11883 --modbus-port 15050

# Full offline demo
python3 -m iotbreach --demo
```

## Safety model

- `assert_lab_target()` rejects any non-loopback / non-RFC5737 host — a hard ceiling.
- No auth token is ever built or stored; only lab placeholders.
- RF protocols are byte-only simulation with dry-run default.
- The kill chain's destructive phase (coil write) is `--dry-run` by default.
- Every finding is written to `reports/` as JSON + Markdown.

## Reports

JSON + Markdown reports are written to `reports/` (gitignored). See
`run_demo()` / `run_kill_chain()` output for the structure.

## Development

```bash
python3 -m unittest discover -s tests    # all unit tests (aim: 130+)
python3 -m py_compile iotbreach/*.py tests/*.py
```

## Live Lab Test Plan

Documented for the plan is a controlled own-lab sequence (localhost sims on a
dedicated test host). Each step proves a concrete attack primitive:

1. **MQTT** — start `mqtt broker-start`; run `mqtt subscribe --topic '#' --leak`.
   Expected proof: CONNACK rc=0 then `LEAKED: admin/config = {...admin_pass...}` plus
   sensor/firmware topics — unauthenticated, wildcard subscribe returns full topic set.
   Grow the same sim with a TLS-fail-open check (CONNECT with `protocol_level=3`), and
   verify QoS-1 `PUBACK` roundtrip.
2. **CoAP** — start `coap sim-start`; `coap get --path .well-known/core` returns
   `</sensor/temperature>` and `</firmware/update>`; `coap firmware-tamper --port 15683`
   proves old-hash ≠ new-hash and `accepted=true`.
3. **UPnP/SSDP** — start `upnp sim-start`; `upnp discover --port 11900` shows
   location/USN; `upnp hnap-inject --port 11900` triggers the SOAP command-injection
   detector (backtick payload in `Password`).
4. **Modbus** — start `modbus sim-start`; `modbus read --fc 3 --addr 0 --qty 4` returns
   temperature=22; `modbus write-coil --addr 0 --value 1` then re-read coil 0: state ON
   (reg did change) — proves no-auth write alters PLC state.
5. **Firmware** — `firmware extract --image fixtures/firmware_v1.bin` lists ELF + SquashFS
   + gzip signatures, entropy summary, embedded `password`/`ssid`/`url` findings.
6. **fwud** — `firmware audit --image fixtures/firmware_v1.bin` (version 1.0.0) matches
   the offline advisory table and flags CRITICAL/HIGH CVEs; recompute hash on a tampered
   copy to prove `tampered=true`.
7. **CAN** — `can replay --count 10` proves identical-frame replay is flagged;
   `can dos --frames 300` pushes the fault counter above threshold → DoS detected.
8. **BLE** — `ble spoof-unlock` on the lock sim flips `gatt_db[0x0002]` to `0x01`;
   `ble battery` returns battery level; CRC-24 matches on ADV PDU parse.
9. **Zigbee/433** — build/ZLL beacon parse and 433 OOK packet round-trip with CRC check;
   replay of a previously seen OOK packet is detected.
10. **Fuzz** — with a sim up, `fuzz run --protocol modbus --port 15050` reports
    `anomalies_found ≥ 1` (truncations, byte overrides, connection errors).
11. **Attack** — `attack run --dry-run` produces `reports/kill_chain.json` with phases
    recon (topics leaked), enumerate (registers read), write (skipped dry-run),
    confirm (heater OFF), report. Re-running without `--dry-run` in the lab flips
    the coil and confirms heater **ON** in the physical-state phase.

All steps run against localhost sockets; no RF emission, no WAN access. Keep the host
profile and scope review before each session.

## Metrics

(as measured — see METRICS.md)

- Unit tests: **134** (see `python3 -m unittest discover -s tests`)
- Demo: `python3 -m iotbreach --demo` exits **0** with per-protocol proofs.
- py_compile on all modules: clean.
- Full numbers (test count, accuracy, timings) live in `METRICS.md` and must be updated
  after each feature/run.

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md).
