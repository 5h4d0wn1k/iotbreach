# Metrics

Measured on `python3.13` / Linux, sep 2026, running every sim on localhost.

## Unit tests

| metric | value |
|---|---|
| Total tests | **136** |
| Test modules | 13 |
| Command | `python3 -m unittest discover -s tests` |
| Result | `OK` (0 failures, 0 errors) |
| Wall time (full suite) | ~54–63 s |

Per-module coverage: common(17), mqtt(22), coap(12), modbus(12), can(8),
ble(11), firmware(17), fwud(10), zigbee(7), fuzz(9), upnp(9), report(3),
cli(11), attack(6).

## Demo

`python3 -m iotbreach --demo` — exit **0**, `Overall: ALL PASS`

| protocol | proof | status |
|---|---|---|
| MQTT | unauth `#` subscribe leaked 5 topics incl. `admin/config` | PASS |
| Modbus | unauth read temp=22; FC5 write coil 0 → verified **ON** | PASS |
| CoAP | firmware UPDATE accepted; old hash ≠ new hash; `accepted=true` | PASS |
| CAN | OBD response on `0x7E8`; identical-frame replay **detected** | PASS |
| BLE | battery read; spoofed GATT write → lock **OPENED** | PASS |
| Kill-chain | recon/enumerate/write(skip)/confirm/report, `success=true` | PASS |

## Attack primitives (offline, per proof run)

| primitive | result | time |
|---|---|---|
| MQTT topic leak (wildcard subscribe) | 5 topics, no creds | <1 s |
| Modbus FC3 read holding | 22 / 55 / 0x0100 / 0 | <1 s |
| Modbus FC5 write coil | heater 0 → 1 (state verified) | <1 s |
| CoAP `.well-known/core` discovery | 5 resources | <1 s |
| CoAP firmware tamper | accepted, hash changed | <1 s |
| UPnP SSDP description | serial+MAC exposed | <1 s |
| HNAP SOAP injection (`` `id` `` in Password) | detected | <1 s |
| CAN OBD-II PID 0x0C response | 0x7E8 | <1 s |
| CAN replay flag | 10 identical frames → detected | <1 s |
| CAN DoS fault counter | 300 frames → `dos_detected=true` | <1 s |
| BLE GATT battery read | 55 (0x37) | <1 s |
| BLE spoof unlock | lock state 0x00 → 0x01 | <1 s |
| Zigbee ZLL beacon parse | channel 11, permit_join | <1 s |
| 433 MHz OOK packet | CRC valid, roundtrip | <1 s |

## Fuzzing (real run against localhost Modbus sim)

| run | iterations | anomalies | errors | elapsed |
|---|---|---|---|---|
| fuzz run (modbus, 200 it) | 200 | 100 | 0 | 0.83 s |
| fuzz run (modbus, 300 it) | 300 | 147 | 0 | 0.62 s |
| fuzz run via CLI (tri, 120 it) | 120 | 55 | 0 | 0.30 s |

Anomaly rates ~ 45–50% across byte-flip/override/truncate/grow/zero-fill
mutators; ≥1 anomaly guaranteed by suite (`test_fuzz`).

## Firmware analysis (fixtures/firmware_v1.bin, 3120 B)

| metric | value |
|---|---|
| Signatures | ELF (0x0), SquashFS little-endian (0x600), gzip (0xc0c) |
| SquashFS compressor | gzip |
| Entropy (mean/max/block 256 B) | 3.0133 / 7.2337 |
| Embedded config findings | password, SSID, URL, api_key, token, admin |
| Filesystem paths | /etc/passwd, /cgi-bin/luci, /www/index.html, … |

## Firmware audit

| fixture | version | CVEs matched | hash check | tamper |
|---|---|---|---|---|
| firmware_v1.bin | 1.0.0 | 8 (incl. 3× CRITICAL) | — | — |
| firmware_v2.bin (patched) | 2.0.0 | 0 | match=true | false |
| v1 + tampered copy | 1.0.0 | 8 | mismatch | **true** |

## Safety / hygiene

| check | result |
|---|---|
| `py_compile iotbreach/*.py tests/*.py` | clean |
| Token-literal scan (AKIA/xoxb/ghp_/sk_live/eyJ) | **0** found |
| `assert_lab_target` rejects non-loopback | verified by tests |
| Git status at release | clean tree, local `main` only, never pushed |