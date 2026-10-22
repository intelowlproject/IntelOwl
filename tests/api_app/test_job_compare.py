# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import unittest
from unittest.mock import MagicMock

from api_app.services.job_compare import (
    compare_jobs,
    compare_plugin_reports,
    compute_dict_diff,
)


class JobCompareServiceTestCase(unittest.TestCase):
    def test_compute_dict_diff_identical(self):
        data_a = {"score": 10, "status": "clean"}
        data_b = {"score": 10, "status": "clean"}
        diff = compute_dict_diff(data_a, data_b)

        self.assertEqual(diff["keys_only_in_a"], [])
        self.assertEqual(diff["keys_only_in_b"], [])
        self.assertEqual(diff["keys_differing"], [])
        self.assertEqual(diff["keys_matching"], ["score", "status"])

    def test_compute_dict_diff_differences(self):
        data_a = {"score": 10, "source": "threat_a"}
        data_b = {"score": 50, "destination": "threat_b"}
        diff = compute_dict_diff(data_a, data_b)

        self.assertEqual(diff["keys_only_in_a"], ["source"])
        self.assertEqual(diff["keys_only_in_b"], ["destination"])
        self.assertEqual(diff["keys_differing"], ["score"])
        self.assertEqual(diff["keys_matching"], [])

    def test_compute_dict_diff_invalid_types(self):
        diff = compute_dict_diff(None, "invalid")
        self.assertEqual(diff["keys_only_in_a"], [])
        self.assertEqual(diff["keys_only_in_b"], [])
        self.assertEqual(diff["keys_differing"], [])
        self.assertEqual(diff["keys_matching"], [])

    def test_compare_plugin_reports(self):
        report_a1 = MagicMock()
        report_a1.config.name = "VirusTotal"
        report_a1.status = "SUCCESS"
        report_a1.report = {"positives": 5}
        report_a1.errors = []
        report_a1.process_time = 1.2

        report_b1 = MagicMock()
        report_b1.config.name = "VirusTotal"
        report_b1.status = "SUCCESS"
        report_b1.report = {"positives": 12}
        report_b1.errors = []
        report_b1.process_time = 1.4

        report_b2 = MagicMock()
        report_b2.config.name = "Shodan"
        report_b2.status = "SUCCESS"
        report_b2.report = {"ports": [80, 443]}
        report_b2.errors = []
        report_b2.process_time = 0.8

        comparison = compare_plugin_reports([report_a1], [report_b1, report_b2])
        self.assertEqual(len(comparison), 2)

        vt_comp = next((c for c in comparison if c["name"] == "VirusTotal"), None)
        self.assertIsNotNone(vt_comp)
        self.assertEqual(vt_comp["present_in"], "both")
        self.assertTrue(vt_comp["has_differences"])
        self.assertEqual(vt_comp["diff_summary"]["keys_differing"], ["positives"])

        shodan_comp = next((c for c in comparison if c["name"] == "Shodan"), None)
        self.assertIsNotNone(shodan_comp)
        self.assertEqual(shodan_comp["present_in"], "job_b")
        self.assertTrue(shodan_comp["has_differences"])

    def test_compare_jobs(self):
        job_a = MagicMock()
        job_a.pk = 101
        job_a.status = "REPORTED_WITHOUT_FAILS"
        job_a.tlp = "CLEAR"
        job_a.is_sample = False
        job_a.analyzable.name = "8.8.8.8"
        job_a.analyzable.classification = "ip"
        job_a.analyzable.mimetype = None
        job_a.analyzable.md5 = None
        job_a.received_request_time = "2026-10-20T10:00:00Z"
        job_a.finished_analysis_time = "2026-10-20T10:01:00Z"
        job_a.process_time = 60.0
        job_a.tags.values_list.return_value = ["malicious", "dns"]
        job_a.errors = []
        job_a.warnings = []

        job_b = MagicMock()
        job_b.pk = 102
        job_b.status = "REPORTED_WITHOUT_FAILS"
        job_b.tlp = "GREEN"
        job_b.is_sample = False
        job_b.analyzable.name = "8.8.8.8"
        job_b.analyzable.classification = "ip"
        job_b.analyzable.mimetype = None
        job_b.analyzable.md5 = None
        job_b.received_request_time = "2026-10-20T11:00:00Z"
        job_b.finished_analysis_time = "2026-10-20T11:01:00Z"
        job_b.process_time = 58.0
        job_b.tags.values_list.return_value = ["dns", "scanner"]
        job_b.errors = []
        job_b.warnings = []

        report_a = MagicMock()
        report_a.config.name = "Shodan"
        report_a.status = "SUCCESS"
        report_a.report = {"ports": [80]}
        report_a.errors = []
        report_a.process_time = 1.0

        report_b = MagicMock()
        report_b.config.name = "Shodan"
        report_b.status = "SUCCESS"
        report_b.report = {"ports": [80, 443]}
        report_b.errors = []
        report_b.process_time = 1.2

        job_a.analyzerreports.select_related.return_value.all.return_value = [report_a]
        job_b.analyzerreports.select_related.return_value.all.return_value = [report_b]
        job_a.connectorreports.select_related.return_value.all.return_value = []
        job_b.connectorreports.select_related.return_value.all.return_value = []

        result = compare_jobs(job_a, job_b)
        self.assertEqual(result["job_a"]["id"], 101)
        self.assertEqual(result["job_b"]["id"], 102)
        self.assertTrue(result["summary"]["same_observable"])
        self.assertTrue(result["summary"]["same_type"])
        self.assertEqual(result["summary"]["total_analyzers_a"], 1)
        self.assertEqual(result["summary"]["total_analyzers_b"], 1)
        self.assertEqual(result["summary"]["common_analyzers_count"], 1)
        self.assertEqual(result["summary"]["differing_analyzers_count"], 1)
        self.assertEqual(result["summary"]["tag_diff"]["shared"], ["dns"])
        self.assertEqual(result["summary"]["tag_diff"]["only_in_a"], ["malicious"])
        self.assertEqual(result["summary"]["tag_diff"]["only_in_b"], ["scanner"])
        job_a.tags.values_list.assert_called_with("label", flat=True)
        job_b.tags.values_list.assert_called_with("label", flat=True)


if __name__ == "__main__":
    unittest.main()
