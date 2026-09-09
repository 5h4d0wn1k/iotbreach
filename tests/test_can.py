"""CAN module tests."""

import time
import unittest
from iotbreach.can_module import (
    build_can_frame, parse_can_frame, build_obd_request, build_obd_response,
    CANBusSim, simulate_can_dos, OBD_PIDS,
)
from iotbreach.common import LAB_HOST


class TestCANFrameBuildParse(unittest.TestCase):
    def test_standard_frame(self):
        data = bytes([0x02, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00])
        frame = build_can_frame(0x7DF, data)
        parsed = parse_can_frame(frame)
        self.assertEqual(parsed["arb_id"], 0x7DF)
        self.assertEqual(parsed["dlc"], 8)
        self.assertEqual(parsed["data"][0:3], bytes([0x02, 0x01, 0x0C]))
        self.assertFalse(parsed["extended"])

    def test_extended_frame(self):
        frame = build_can_frame(0x18FEF100, b"\x01\x02\x03\x04\x05\x06\x07\x08", extended=True)
        parsed = parse_can_frame(frame)
        self.assertTrue(parsed["extended"])

    def test_short_data_padded(self):
        frame = build_can_frame(0x100, b"\x01\x02")
        parsed = parse_can_frame(frame)
        self.assertEqual(parsed["dlc"], 2)
        self.assertEqual(parsed["data"], b"\x01\x02")


class TestOBD(unittest.TestCase):
    def test_build_request(self):
        req = build_obd_request(0x0C)  # RPM
        parsed = parse_can_frame(req)
        self.assertEqual(parsed["arb_id"], 0x7DF)
        self.assertEqual(parsed["data"][1], 0x01)  # mode

    def test_build_response(self):
        resp = build_obd_response(0x0C, 0x1A)  # RPM
        parsed = parse_can_frame(resp)
        self.assertEqual(parsed["arb_id"], 0x7E8)
        self.assertEqual(parsed["data"][2], 0x0C)

    def test_obd_pids_known(self):
        self.assertIn(0x0C, OBD_PIDS)
        self.assertIn(0x0D, OBD_PIDS)
        self.assertIn(0x05, OBD_PIDS)


class TestCANBusSim(unittest.TestCase):
    def setUp(self):
        self.sim = CANBusSim()
        self.sim.start()
        time.sleep(0.3)

    def tearDown(self):
        self.sim.stop()

    def test_replay_detection(self):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((LAB_HOST, self.sim.port))
        frame = build_can_frame(0x7DF, bytes([0x02, 0x01, 0x0C]))
        # Send same frame multiple times
        for _ in range(10):
            s.sendall(frame)
        s.close()
        time.sleep(0.3)
        self.assertTrue(self.sim.replay_detected)

    def test_do_s_detection(self):
        result = simulate_can_dos(LAB_HOST, self.sim.port, 300)
        self.assertGreater(result["frames_sent"], 0)
        # After 300 frames, fault counter should be > 200
        time.sleep(0.5)
        self.assertTrue(self.sim.dos_detected)


if __name__ == "__main__":
    unittest.main()
