from unittest.mock import Mock, patch

from api_app.analyzers_manager.observable_analyzers.shodan import Shodan
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class ShodanTestCase(BaseAnalyzerTest):
    analyzer_class = Shodan

    @staticmethod
    def get_mocked_response():
        # Return different responses based on analysis type using side_effect
        def _mocked_requests_get(url, params=None, **kwargs):
            if "honeyscore" in url:
                return MockUpResponse(0.5, 200)
            else:
                return MockUpResponse(
                    {
                        "ip_str": "8.8.8.8",
                        "ports": [53, 443],
                        "hostnames": ["dns.google"],
                    },
                    200,
                )

        return patch("requests.get", side_effect=_mocked_requests_get)

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "fake_api_key",
            "shodan_analysis": "search",  # default mode for tests
        }

    def test_update_data_model_search(self):
        analyzer = Shodan(config=Mock())
        analyzer.shodan_analysis = "search"
        analyzer.report = Mock()
        analyzer.report.report = {
            "ip_str": "8.8.8.8",
            "org": "Google LLC",
            "isp": "Google LLC",
            "country_code": "US",
            "asn": "AS15169",
            "ports": [53, 443],
            "hostnames": ["dns.google"],
            "tags": ["vpn", "tor", "scanner"],
            "vulns": ["CVE-2019-11510"],
        }
        mock_data_model = Mock()
        mock_data_model.additional_info = {}
        mock_data_model.tags = []
        mock_data_model.resolutions = []
        mock_data_model.evaluation = None
        mock_data_model.reliability = 5

        analyzer._update_data_model(mock_data_model)

        self.assertEqual(mock_data_model.org_name, "Google LLC")
        self.assertEqual(mock_data_model.isp, "Google LLC")
        self.assertEqual(mock_data_model.country_code, "US")
        self.assertEqual(mock_data_model.asn, 15169)
        self.assertEqual(mock_data_model.resolutions, ["dns.google"])
        self.assertEqual(mock_data_model.additional_info["ports"], [53, 443])
        self.assertEqual(mock_data_model.additional_info["vulnerabilities"], ["CVE-2019-11510"])
        self.assertIn("anonymizer", mock_data_model.tags)
        self.assertIn("tor_exit_node", mock_data_model.tags)
        self.assertIn("scanner", mock_data_model.tags)
        self.assertEqual(mock_data_model.tags.count("anonymizer"), 1)
        self.assertIsNone(mock_data_model.evaluation)

    def test_update_data_model_search_malicious_tags(self):
        analyzer = Shodan(config=Mock())
        analyzer.shodan_analysis = "search"
        analyzer.report = Mock()
        analyzer.report.report = {
            "tags": ["botnet", "c2"],
        }
        mock_data_model = Mock()
        mock_data_model.additional_info = {}
        mock_data_model.tags = []
        mock_data_model.resolutions = []
        mock_data_model.evaluation = None

        analyzer._update_data_model(mock_data_model)

        self.assertEqual(mock_data_model.evaluation, "malicious")
        self.assertEqual(mock_data_model.reliability, 8)
        self.assertIn("malware", mock_data_model.tags)

    def test_update_data_model_honeyscore(self):
        analyzer = Shodan(config=Mock())
        analyzer.shodan_analysis = "honeyscore"
        analyzer.report = Mock()
        analyzer.report.report = {"honeyscore": 0.8}
        mock_data_model = Mock()
        mock_data_model.additional_info = {}
        mock_data_model.evaluation = None

        analyzer._update_data_model(mock_data_model)

        self.assertEqual(mock_data_model.additional_info, {"honeyscore": 0.8})
        self.assertIsNone(mock_data_model.evaluation)
