"""iotbreach CLI — main entry point with argparse subcommands."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="iotbreach",
        description="IoT/SCADA/embedded offensive security framework (offline lab only)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", type=str, default=None, help="Path to YAML/JSON config file")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Target host (localhost only)")
    parser.add_argument("--demo", action="store_true", help="Run full offline demo")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ---- mqtt ----
    p_mqtt = sub.add_parser("mqtt", help="MQTT protocol attack & broker sim")
    mqtt_sub = p_mqtt.add_subparsers(dest="action")
    mqtt_sub.add_parser("broker-start", help="Start MQTT broker simulator")
    p_mqtt_pub = mqtt_sub.add_parser("publish", help="Publish message to topic")
    p_mqtt_pub.add_argument("--topic", required=True)
    p_mqtt_pub.add_argument("--message", required=True)
    p_mqtt_pub.add_argument("--port", type=int, default=11883)
    p_mqtt_sub = mqtt_sub.add_parser("subscribe", help="Subscribe and dump topics")
    p_mqtt_sub.add_argument("--topic", default="#")
    p_mqtt_sub.add_argument("--port", type=int, default=11883)
    p_mqtt_sub.add_argument("--leak", action="store_true", help="Demonstrate unauth topic leak")
    p_mqtt_sub.add_argument("--repeat", type=int, default=1, help="Repeat count")

    # ---- coap ----
    p_coap = sub.add_parser("coap", help="CoAP protocol attack & UDP sim")
    coap_sub = p_coap.add_subparsers(dest="action")
    coap_sub.add_parser("sim-start", help="Start CoAP UDP simulator")
    coap_get = coap_sub.add_parser("get", help="CoAP GET request")
    coap_get.add_argument("--path", required=True)
    coap_get.add_argument("--port", type=int, default=15683)
    coap_fw = coap_sub.add_parser("firmware-tamper", help="Demonstrate firmware binary swap")
    coap_fw.add_argument("--port", type=int, default=15683)
    coap_fw.add_argument("--repeat", type=int, default=1)

    # ---- upnp ----
    p_upnp = sub.add_parser("upnp", help="UPnP/SSDP/HNAP exploit sim")
    upnp_sub = p_upnp.add_subparsers(dest="action")
    upnp_sub.add_parser("sim-start", help="Start UPnP simulator")
    upnp_disc = upnp_sub.add_parser("discover", help="SSDP M-SEARCH discovery")
    upnp_disc.add_argument("--port", type=int, default=11900)
    upnp_inject = upnp_sub.add_parser("hnap-inject", help="SOAP command injection demo")
    upnp_inject.add_argument("--port", type=int, default=11900)

    # ---- modbus ----
    p_modbus = sub.add_parser("modbus", help="Modbus-TCP attack & slave sim")
    modbus_sub = p_modbus.add_subparsers(dest="action")
    modbus_sub.add_parser("sim-start", help="Start Modbus slave simulator")
    mb_read = modbus_sub.add_parser("read", help="Read registers/coils")
    mb_read.add_argument("--fc", type=int, default=3, choices=[1,2,3,4], help="Function code")
    mb_read.add_argument("--addr", type=int, default=0)
    mb_read.add_argument("--qty", type=int, default=4)
    mb_read.add_argument("--port", type=int, default=15050)
    mb_write = modbus_sub.add_parser("write-coil", help="Write single coil (FC5)")
    mb_write.add_argument("--addr", type=int, default=0)
    mb_write.add_argument("--value", type=int, default=1, choices=[0,1])
    mb_write.add_argument("--port", type=int, default=15050)

    # ---- firmware ----
    p_fw = sub.add_parser("firmware", help="Firmware extraction & analysis")
    fw_sub = p_fw.add_subparsers(dest="action")
    fw_extract = fw_sub.add_parser("extract", help="Extract signatures + entropy + config")
    fw_extract.add_argument("--image", required=True, help="Path to firmware image")
    fw_audit = fw_sub.add_parser("audit", help="Firmware audit (version, CVEs, tamper)")
    fw_audit.add_argument("--image", required=True)
    fw_audit.add_argument("--hash", default=None, help="Expected SHA-256 hash")
    fw_audit.add_argument("--version", default=None, help="Override version string")

    # ---- can ----
    p_can = sub.add_parser("can", help="CAN bus attack sim")
    can_sub = p_can.add_subparsers(dest="action")
    can_sub.add_parser("sim-start", help="Start CAN bus simulator")
    can_obd = can_sub.add_parser("obd", help="Send OBD-II request")
    can_obd.add_argument("--pid", type=lambda x: int(x, 0), default=0x0C)
    can_obd.add_argument("--port", type=int, default=17000)
    can_replay = can_sub.add_parser("replay", help="Replay attack demo")
    can_replay.add_argument("--count", type=int, default=5)
    can_replay.add_argument("--port", type=int, default=17000)
    can_dos = can_sub.add_parser("dos", help="DoS simulation")
    can_dos.add_argument("--frames", type=int, default=300)
    can_dos.add_argument("--port", type=int, default=17000)

    # ---- ble ----
    p_ble = sub.add_parser("ble", help="BLE GATT attack sim")
    ble_sub = p_ble.add_subparsers(dest="action")
    ble_sub.add_parser("sim-start", help="Start BLE smart lock simulator")
    ble_battery = ble_sub.add_parser("battery", help="Read battery level GATT")
    ble_battery.add_argument("--port", type=int, default=17001)
    ble_lock = ble_sub.add_parser("lock-state", help="Read lock state GATT")
    ble_lock.add_argument("--port", type=int, default=17001)
    ble_spoof = ble_sub.add_parser("spoof-unlock", help="Spoof authenticated write to open lock")
    ble_spoof.add_argument("--port", type=int, default=17001)

    # ---- zigbee_433 ----
    p_zig = sub.add_parser("zigbee-433", help="Zigbee beacon & 433 MHz OOK")
    zig_sub = p_zig.add_subparsers(dest="action")
    zig_sub.add_parser("sim-start", help="Start Zigbee/433 simulator")
    zig_beacon = zig_sub.add_parser("beacon", help="Build/parse Zigbee beacon")
    zig_ook = zig_sub.add_parser("ook", help="Build/parse 433 MHz OOK packet")

    # ---- fuzz ----
    p_fuzz = sub.add_parser("fuzz", help="Protocol fuzzer")
    fuzz_sub = p_fuzz.add_subparsers(dest="action")
    fuzz_run = fuzz_sub.add_parser("run", help="Run fuzzer against protocol sim")
    fuzz_run.add_argument("--protocol", required=True, choices=["mqtt", "modbus", "can", "ble"])
    fuzz_run.add_argument("--port", type=int, required=True)
    fuzz_run.add_argument("--iterations", type=int, default=200)
    fuzz_run.add_argument("--host", default="127.0.0.1")

    # ---- attack ----
    p_attack = sub.add_parser("attack", help="Full kill-chain simulation")
    atk_sub = p_attack.add_subparsers(dest="action")
    atk_run = atk_sub.add_parser("run", help="Run kill-chain on localhost sims")
    atk_run.add_argument("--dry-run", action="store_true", default=True)
    atk_run.add_argument("--mqtt-port", type=int, default=11883)
    atk_run.add_argument("--modbus-port", type=int, default=15050)
    atk_run.add_argument("--repeat", type=int, default=1)
    atk_demo = atk_sub.add_parser("demo", help="Full automated demo (all sims + kill chain)")

    # ---- demo ----
    sub.add_parser("demo", help="Run full demo of all protocols + kill chain")

    # ---- parse ----
    p_parse = sub.add_parser("parse", help="Parse raw protocol packets")
    parse_sub = p_parse.add_subparsers(dest="action")
    p_mqtt_parse = parse_sub.add_parser("mqtt", help="Parse MQTT packet hex")
    p_mqtt_parse.add_argument("--hex", required=True)
    p_coap_parse = parse_sub.add_parser("coap", help="Parse CoAP message hex")
    p_coap_parse.add_argument("--hex", required=True)
    p_modbus_parse = parse_sub.add_parser("modbus", help="Parse Modbus packet hex")
    p_modbus_parse.add_argument("--hex", required=True)

    args = parser.parse_args(argv)

    if args.demo:
        return _cmd_demo()

    if args.command is None:
        parser.print_help()
        return 0

    # ---- Dispatch ----
    if args.command == "demo":
        return _cmd_demo()
    elif args.command == "mqtt":
        return _cmd_mqtt(args)
    elif args.command == "coap":
        return _cmd_coap(args)
    elif args.command == "upnp":
        return _cmd_upnp(args)
    elif args.command == "modbus":
        return _cmd_modbus(args)
    elif args.command == "firmware":
        return _cmd_firmware(args)
    elif args.command == "can":
        return _cmd_can(args)
    elif args.command == "ble":
        return _cmd_ble(args)
    elif args.command == "zigbee-433":
        return _cmd_zigbee(args)
    elif args.command == "fuzz":
        return _cmd_fuzz(args)
    elif args.command == "attack":
        return _cmd_attack(args)
    elif args.command == "parse":
        return _cmd_parse(args)

    parser.print_help()
    return 0


# ============================================================================
# Command implementations
# ============================================================================

def _cmd_demo() -> int:
    """Run full demo of all protocols."""
    from .mqtt_module import MQTTBrokerSim, build_connect, build_subscribe, build_disconnect, parse_packet, recv_packet
    from .coap_module import CoAPSim, build_get, build_put, parse_message, sha256
    from .modbus_module import ModbusSlaveSim, modbus_read, modbus_write_coil, FC_READ_HOLDING, FC_READ_COILS
    from .can_module import CANBusSim, build_can_frame, build_obd_request, build_obd_response, parse_can_frame
    from .ble_module import BLELockSim, ble_read_battery, ble_read_lock_state, ble_spoof_unlock
    from .attack_module import run_kill_chain
    from .common import LAB_HOST
    import socket
    import time
    import secrets

    print("=" * 60)
    print("  iotbreach v1.0.0 — Full Offline Demo")
    print("  ALL SIMS ON LOCALHOST — NO REAL HARDWARE")
    print("=" * 60)

    results = {}
    errors = []

    # ---- MQTT Demo ----
    print("\n[1/6] MQTT Broker Sim + Unauth Subscribe")
    broker = MQTTBrokerSim()
    broker.start()
    time.sleep(0.3)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((LAB_HOST, broker.port))
        s.sendall(build_connect("demo-client"))
        data = recv_packet(s)
        connack = parse_packet(data)
        assert connack["type_name"] == "CONNACK", f"Expected CONNACK, got {connack['type_name']}"
        s.sendall(build_subscribe(1, "#"))
        data = recv_packet(s)
        suback = parse_packet(data)
        assert suback["type_name"] == "SUBACK"
        topics = []
        while True:
            try:
                data = recv_packet(s, timeout=1)
            except socket.timeout:
                break
            if data is None:
                break
            msg = parse_packet(data)
            if msg.get("topic"):
                topics.append(msg["topic"])
        s.sendall(build_disconnect())
        s.close()
        print(f"  MQTT topics leaked (unauth subscribe): {topics}")
        assert len(topics) > 0, "No MQTT topics leaked"
        results["mqtt_topics_leaked"] = topics
        results["mqtt_status"] = "PASS"
    except Exception as e:
        errors.append(f"MQTT: {e}")
        results["mqtt_status"] = f"FAIL: {e}"
    finally:
        broker.stop()

    # ---- Modbus Demo ----
    print("\n[2/6] Modbus Slave Sim + Unauth Read/Write")
    slave = ModbusSlaveSim()
    slave.start()
    time.sleep(0.3)
    try:
        regs = modbus_read(LAB_HOST, slave.port, FC_READ_HOLDING, 0, 4)
        data = regs.get("data", b"")
        temp = int.from_bytes(data[0:2], "big") if len(data) >= 2 else 0
        print(f"  Modbus unauth read: temp_setpoint={temp}")
        assert temp == 22, f"Expected temp=22, got {temp}"
        results["modbus_temp_before"] = temp

        write_res = modbus_write_coil(LAB_HOST, slave.port, 0, True)
        assert write_res.get("function_code") == 0x05
        print(f"  Modbus FC5 write coil 0=True (heater ON)")

        coils = modbus_read(LAB_HOST, slave.port, FC_READ_COILS, 0, 4)
        coil_data = coils.get("data", b"")
        heater = bool(coil_data[0] & 0x01) if coil_data else False
        print(f"  Modbus coil 0 state after write: {'ON' if heater else 'OFF'}")
        assert heater is True, "Heater coil did not change to ON"
        results["modbus_heater_after"] = "ON"
        results["modbus_status"] = "PASS"
    except Exception as e:
        errors.append(f"Modbus: {e}")
        results["modbus_status"] = f"FAIL: {e}"
    finally:
        slave.stop()

    # ---- CoAP Demo ----
    print("\n[3/6] CoAP UDP Sim + Firmware Tamper")
    coap = CoAPSim()
    coap.start()
    time.sleep(0.3)
    try:
        from .coap_module import coap_get, coap_put
        resp = coap_get(LAB_HOST, coap.port, ".well-known/core")
        print(f"  CoAP resource discovery: {resp['payload'][:80]}")
        old_hash = coap.firmware_hash
        new_fw = b"\x89PNG_NEW" + secrets.token_bytes(32)
        resp = coap_put(LAB_HOST, coap.port, "firmware/update", new_fw)
        new_hash = coap.firmware_hash
        print(f"  CoAP firmware update: old_hash={old_hash[:16]}... new_hash={new_hash[:16]}...")
        assert old_hash != new_hash, "Hash did not change"
        assert coap.firmware_accepted is True
        results["coap_fw_hash_changed"] = True
        results["coap_fw_accepted"] = True
        results["coap_status"] = "PASS"
    except Exception as e:
        errors.append(f"CoAP: {e}")
        results["coap_status"] = f"FAIL: {e}"
    finally:
        coap.stop()

    # ---- CAN Demo ----
    print("\n[4/6] CAN Bus Sim + Replay Detection")
    can = CANBusSim()
    can.start()
    time.sleep(0.3)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((LAB_HOST, can.port))
        frame = build_can_frame(0x7DF, bytes([0x02, 0x01, 0x0C]))
        s.sendall(frame)
        try:
            resp = s.recv(13)
            if resp:
                parsed_resp = parse_can_frame(resp)
                print(f"  CAN OBD response: id={parsed_resp['arb_id_hex']}")
        except socket.timeout:
            pass
        # Replay
        for _ in range(5):
            s.sendall(frame)
        s.close()
        time.sleep(0.2)
        assert can.replay_detected is True, "Replay not detected"
        print(f"  CAN replay detected: {can.replay_detected}")
        results["can_replay_detected"] = True
        results["can_status"] = "PASS"
    except Exception as e:
        errors.append(f"CAN: {e}")
        results["can_status"] = f"FAIL: {e}"
    finally:
        can.stop()

    # ---- BLE Demo ----
    print("\n[5/6] BLE Smart Lock Sim + Spoof Unlock")
    lock = BLELockSim()
    lock.start()
    time.sleep(0.3)
    try:
        battery = ble_read_battery(LAB_HOST, lock.port)
        print(f"  BLE battery read: {battery.get('value', b'').hex()}")
        lock_state = ble_read_lock_state(LAB_HOST, lock.port)
        print(f"  BLE lock state: {lock_state.get('value', b'').hex()} (0=locked)")
        unlock = ble_spoof_unlock(LAB_HOST, lock.port)
        print(f"  BLE spoof unlock command sent: {unlock}")
        assert lock.lock_opened is True, "Lock was not opened"
        print(f"  BLE lock OPENED via spoofed write: {lock.lock_opened}")
        results["ble_lock_opened"] = True
        results["ble_status"] = "PASS"
    except Exception as e:
        errors.append(f"BLE: {e}")
        results["ble_status"] = f"FAIL: {e}"
    finally:
        lock.stop()

    # ---- Kill Chain Demo ----
    print("\n[6/6] ICS/SCADA Kill-Chain (dry-run)")
    try:
        broker2 = MQTTBrokerSim()
        slave2 = ModbusSlaveSim()
        broker2.start()
        slave2.start()
        time.sleep(0.5)
        chain = run_kill_chain(
            mqtt_port=broker2.port, modbus_port=slave2.port,
            host=LAB_HOST, dry_run=True,
        )
        print(f"  Kill chain phases completed: {len(chain.get('phases', []))}")
        print(f"  Kill chain success: {chain.get('success')}")
        results["kill_chain_success"] = chain.get("success")
        results["kill_chain_phases"] = len(chain.get("phases", []))
        results["kill_chain_report"] = chain.get("report_json")
        results["attack_status"] = "PASS"
        broker2.stop()
        slave2.stop()
    except Exception as e:
        errors.append(f"Attack: {e}")
        results["attack_status"] = f"FAIL: {e}"

    # ---- Summary ----
    print("\n" + "=" * 60)
    print("  DEMO SUMMARY")
    print("=" * 60)
    for key, val in results.items():
        if key.endswith("_status"):
            status_icon = "PASS" if val == "PASS" else "FAIL"
            print(f"  {key}: {status_icon}")
    if errors:
        print(f"\n  ERRORS: {len(errors)}")
        for e in errors:
            print(f"    - {e}")

    # Token scan
    from .common import scan_for_tokens
    all_text = json.dumps(results)
    tokens = scan_for_tokens(all_text)
    assert not tokens, f"Token-shaped literals found: {tokens}"

    all_passed = all(v == "PASS" for k, v in results.items() if k.endswith("_status"))
    print(f"\n  Overall: {'ALL PASS' if all_passed else 'SOME FAILURES'}")
    return 0 if all_passed else 1


def _cmd_mqtt(args: argparse.Namespace) -> int:
    from .mqtt_module import MQTTBrokerSim, build_connect, build_subscribe, build_publish, build_disconnect, parse_packet, recv_packet
    from .common import LAB_HOST
    import socket
    import time

    if args.action == "broker-start":
        broker = MQTTBrokerSim()
        broker.start()
        print(f"MQTT broker sim on {LAB_HOST}:{broker.port}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            broker.stop()
    elif args.action == "subscribe" or (getattr(args, 'leak', False)):
        repeat = getattr(args, 'repeat', 1)
        for i in range(repeat):
            print(f"\n--- MQTT subscribe round {i+1}/{repeat} ---")
            _mqtt_subscribe_leak(args.host, args.port, getattr(args, 'topic', '#'))
    return 0


def _mqtt_subscribe_leak(host: str, port: int, topic: str) -> None:
    from .mqtt_module import build_connect, build_subscribe, build_disconnect, parse_packet, recv_packet
    from .common import scan_for_tokens
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    s.sendall(build_connect("leak-client"))
    data = recv_packet(s)
    connack = parse_packet(data)
    print(f"  CONNACK: rc={connack.get('return_code')}")
    s.sendall(build_subscribe(1, topic))
    data = recv_packet(s)
    suback = parse_packet(data)
    print(f"  SUBACK: rc={suback.get('return_codes')}")
    messages = []
    while True:
        try:
            data = recv_packet(s, timeout=1)
        except socket.timeout:
            break
        if data is None:
            break
        try:
            msg = parse_packet(data)
        except ValueError:
            break
        messages.append(msg)
        if msg.get("topic") and msg.get("payload"):
            payload_str = msg["payload"].decode("utf-8", errors="replace")
            print(f"  LEAKED: {msg['topic']} = {payload_str}")
            tokens = scan_for_tokens(payload_str)
            if tokens:
                print(f"  TOKEN DETECTED: {tokens}")
    s.sendall(build_disconnect())
    s.close()
    print(f"  Total topics leaked: {len(messages)}")


def _cmd_coap(args: argparse.Namespace) -> int:
    from .coap_module import CoAPSim, coap_get, coap_put, sha256
    from .common import LAB_HOST
    import time
    import secrets

    if args.action == "sim-start":
        sim = CoAPSim()
        sim.start()
        print(f"CoAP UDP sim on {LAB_HOST}:{sim.port}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            sim.stop()
    elif args.action == "get":
        resp = coap_get(args.host, args.port, args.path)
        print(f"  {resp['code_str']} {resp['uri_path']}: {resp['payload'][:200]}")
    elif args.action == "firmware-tamper":
        # Attack an existing CoAP sim: verify -> tamper -> re-verify
        old = coap_get(args.host, args.port, "firmware/verify")
        old_hash = old["payload"].decode("utf-8", errors="replace")
        for i in range(args.repeat):
            new_fw = b"\x89PNG" + secrets.token_bytes(64)
            resp = coap_put(args.host, args.port, "firmware/update", new_fw)
            if resp["code"] != 0x44:
                print(f"  Round {i+1}: update rejected ({resp['code_str']})")
                return 1
            print(f"  Round {i+1}: firmware tamper PUT accepted (2.04 Changed)")
        new = coap_get(args.host, args.port, "firmware/verify")
        new_hash = new["payload"].decode("utf-8", errors="replace")
        print(f"  old_hash: {old_hash[:40]}")
        print(f"  new_hash: {new_hash[:40]}")
        if old_hash != new_hash:
            print("  PASS: Firmware tamper accepted, hash changed")
            return 0
        print("  FAIL: hash did not change")
        return 1
    return 0


def _cmd_upnp(args: argparse.Namespace) -> int:
    from .upnp_module import UPnPSim, upnp_discover, upnp_get_description, upnp_hnap_inject
    from .common import LAB_HOST
    import time

    if args.action == "sim-start":
        sim = UPnPSim()
        sim.start()
        print(f"UPnP sim on {LAB_HOST}:{sim.tcp_port} (SSDP:{sim.ssdp_port})")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            sim.stop()
    elif args.action == "discover":
        resp = upnp_discover(args.host, args.port)
        print(f"  SSDP response: {resp}")
    elif args.action == "hnap-inject":
        sim = UPnPSim(tcp_port=0, ssdp_port=0)
        sim.start()
        time.sleep(0.3)
        try:
            desc = upnp_get_description(args.host, sim.tcp_port)
            print(f"  Device: {desc.get('modelName')} / {desc.get('friendlyName')}")
            print(f"  Serial: {desc.get('serialNumber')}")
            resp = upnp_hnap_inject(args.host, sim.tcp_port)
            print(f"  HNAP inject response: {resp.get('status')}")
            assert sim.injection_triggered, "Injection not triggered"
            print("  PASS: Command injection detected in SOAP Password field")
        finally:
            sim.stop()
    return 0


def _cmd_modbus(args: argparse.Namespace) -> int:
    from .modbus_module import ModbusSlaveSim, modbus_read, modbus_write_coil
    from .modbus_module import FC_READ_COILS, FC_READ_DISCRETE, FC_READ_HOLDING, FC_READ_INPUT
    from .common import LAB_HOST
    import time

    FC_MAP = {1: FC_READ_COILS, 2: FC_READ_DISCRETE, 3: FC_READ_HOLDING, 4: FC_READ_INPUT}

    if args.action == "sim-start":
        slave = ModbusSlaveSim()
        slave.start()
        print(f"Modbus slave sim on {LAB_HOST}:{slave.port}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            slave.stop()
    elif args.action == "read":
        fc = FC_MAP[args.fc]
        result = modbus_read(args.host, args.port, fc, args.addr, args.qty)
        data = result.get("data", b"")
        print(f"  FC{args.fc} @ {args.addr}: {data.hex()}")
        # Decode holding registers
        if args.fc == 3:
            for i in range(args.qty // 2):
                val = int.from_bytes(data[i*2:i*2+2], "big")
                print(f"    Register {args.addr+i}: {val}")
    elif args.action == "write-coil":
        result = modbus_write_coil(args.host, args.port, args.addr, bool(args.value))
        print(f"  FC5 write coil {args.addr} = {args.value}: {result}")
        # Verify
        time.sleep(0.1)
        verify = modbus_read(args.host, args.port, FC_READ_COILS, args.addr, 4)
        coil_data = verify.get("data", b"")
        coil_state = bool(coil_data[0] & 0x01) if coil_data else False
        print(f"  Verified coil {args.addr} state: {'ON' if coil_state else 'OFF'}")
    return 0


def _cmd_firmware(args: argparse.Namespace) -> int:
    from pathlib import Path
    if args.action == "extract":
        data = Path(args.image).read_bytes()
        from .firmware_module import analyze_firmware
        result = analyze_firmware(data)
        print(json.dumps(result, indent=2, default=str))
    elif args.action == "audit":
        data = Path(args.image).read_bytes()
        from .fwud_module import audit_firmware
        result = audit_firmware(data, expected_hash=args.hash, version_override=args.version)
        print(json.dumps(result, indent=2, default=str))
    return 0


def _cmd_can(args: argparse.Namespace) -> int:
    from .can_module import CANBusSim, build_can_frame, build_obd_request, parse_can_frame, simulate_can_dos
    from .common import LAB_HOST
    import socket
    import time

    if args.action == "sim-start":
        sim = CANBusSim()
        sim.start()
        print(f"CAN bus sim on {LAB_HOST}:{sim.port}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            sim.stop()
    elif args.action == "obd":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((args.host, args.port))
        req = build_obd_request(args.pid)
        s.sendall(req)
        try:
            resp = s.recv(13)
            if resp:
                parsed = parse_can_frame(resp)
                print(f"  OBD PID 0x{args.pid:02X}: {parsed['data_hex']}")
        except socket.timeout:
            print("  No response (timeout)")
        s.close()
    elif args.action == "replay":
        sim = CANBusSim(port=0)
        sim.start()
        time.sleep(0.3)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((args.host, sim.port))
            frame = build_can_frame(0x7DF, bytes([0x02, 0x01, 0x0C]))
            for i in range(args.count):
                s.sendall(frame)
            s.close()
            time.sleep(0.3)
            assert sim.replay_detected, "Replay not detected"
            print(f"  PASS: CAN replay detected after {args.count} identical frames")
        finally:
            sim.stop()
    elif args.action == "dos":
        result = simulate_can_dos(args.host, args.port, args.frames)
        print(f"  DoS: {result['frames_sent']} frames sent")
    return 0


def _cmd_ble(args: argparse.Namespace) -> int:
    from .ble_module import BLELockSim, ble_read_battery, ble_read_lock_state, ble_spoof_unlock
    from .common import LAB_HOST
    import time

    if args.action == "sim-start":
        sim = BLELockSim()
        sim.start()
        print(f"BLE smart lock sim on {LAB_HOST}:{sim.port}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            sim.stop()
    elif args.action == "battery":
        result = ble_read_battery(args.host, args.port)
        print(f"  Battery: {result}")
    elif args.action == "lock-state":
        result = ble_read_lock_state(args.host, args.port)
        print(f"  Lock state: {result}")
    elif args.action == "spoof-unlock":
        sim = BLELockSim(port=0)
        sim.start()
        time.sleep(0.3)
        try:
            result = ble_spoof_unlock(args.host, sim.port)
            print(f"  Spoof unlock result: {result}")
            assert sim.lock_opened, "Lock was not opened"
            print("  PASS: Smart lock OPENED via spoofed GATT write")
        finally:
            sim.stop()
    return 0


def _cmd_zigbee(args: argparse.Namespace) -> int:
    from .zigbee_module import build_zigbee_beacon, parse_zigbee_beacon, build_ook_packet, parse_ook_packet

    if args.action == "sim-start":
        from .zigbee_module import Zigbee433Sim
        from .common import LAB_HOST
        import time
        sim = Zigbee433Sim()
        sim.start()
        print(f"Zigbee/433 sim on {LAB_HOST}:{sim.port}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            sim.stop()
    elif args.action == "beacon":
        beacon = build_zigbee_beacon(permit_join=True)
        parsed = parse_zigbee_beacon(beacon)
        print(f"  Zigbee beacon: {parsed}")
    elif args.action == "ook":
        pkt = build_ook_packet(protocol_id=0x42, command=0x01, payload=bytes([0x10, 0x20, 0x30]))
        parsed = parse_ook_packet(pkt)
        print(f"  433MHz OOK packet: {parsed}")
    return 0


def _cmd_fuzz(args: argparse.Namespace) -> int:
    from .fuzz_module import (
        get_mqtt_connect_fixture, get_mqtt_publish_fixture,
        get_modbus_read_fixture, get_modbus_write_fixture,
        get_can_frame_fixture, fuzz_protocol,
    )
    from .common import LAB_HOST

    fixture_map = {
        "mqtt": get_mqtt_connect_fixture(),
        "modbus": get_modbus_read_fixture(),
        "can": get_can_frame_fixture(),
    }
    fixture = fixture_map.get(args.protocol)
    if fixture is None:
        print(f"No fixture for protocol: {args.protocol}")
        return 1

    result = fuzz_protocol(
        args.protocol, fixture, args.host, args.port,
        protocol="tcp", iterations=args.iterations,
    )
    print(json.dumps(result, indent=2))
    return 0


def _cmd_attack(args: argparse.Namespace) -> int:
    from .attack_module import run_kill_chain
    if args.action == "demo":
        from .attack_module import run_demo
        result = run_demo()
        print(json.dumps(result, indent=2, default=str))
        return 0 if result.get("success") else 1
    elif args.action == "run":
        result = run_kill_chain(
            mqtt_port=args.mqtt_port,
            modbus_port=args.modbus_port,
            host=args.host,
            dry_run=args.dry_run,
        )
        print(json.dumps(result, indent=2, default=str))
        return 0 if result.get("success") else 1
    return 0


def _cmd_parse(args: argparse.Namespace) -> int:
    if args.action == "mqtt":
        from .mqtt_module import parse_packet
        data = bytes.fromhex(args.hex)
        result = parse_packet(data)
        print(json.dumps(result, indent=2, default=str))
    elif args.action == "coap":
        from .coap_module import parse_message
        data = bytes.fromhex(args.hex)
        result = parse_message(data)
        print(json.dumps(result, indent=2, default=str))
    elif args.action == "modbus":
        from .modbus_module import parse_mbap
        data = bytes.fromhex(args.hex)
        result = parse_mbap(data)
        print(json.dumps(result, indent=2, default=str))
    return 0
