"""Report module tests."""

import json
import tempfile
import unittest
from pathlib import Path

from iotbreach.report import ReportBuilder


class TestReportBuilder(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.reports_dir = Path(self.tmpdir.name) / "reports"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_add_finding(self):
        rb = ReportBuilder("Test", str(self.reports_dir))
        rb.add_finding("HIGH", "test", "detail")
        self.assertEqual(len(rb.findings), 1)
        self.assertEqual(rb.findings[0]["severity"], "HIGH")

    def test_add_phase(self):
        rb = ReportBuilder("Test", str(self.reports_dir))
        rb.add_phase("phase1", "completed", "detail")
        self.assertEqual(len(rb.phases), 1)

    def test_save(self):
        rb = ReportBuilder("Test", str(self.reports_dir))
        rb.add_finding("CRITICAL", "test", "detail")
        rb.add_phase("phase1", "completed", "detail")
        jp, mp = rb.save("test_report")
        self.assertTrue(jp.exists())
        self.assertTrue(mp.exists())

        data = json.loads(jp.read_text())
        self.assertEqual(data["summary"]["total_findings"], 1)
        self.assertEqual(data["summary"]["by_severity"]["CRITICAL"], 1)

        md = mp.read_text()
        self.assertIn("# Test", md)
        self.assertIn("- [CRITICAL]", md)


if __name__ == "__main__":
    unittest.main()