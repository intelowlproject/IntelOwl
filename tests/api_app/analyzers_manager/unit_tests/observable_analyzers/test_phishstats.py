
from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.phishstats import PhishStats
from api_app.choices import Classification
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class PhishStatsTestCase(BaseAnalyzerTest):
    analyzer_class = PhishStats

    @staticmethod
    def get_mocked_response():
        mock_json_response = [
            {
                "id": 12345,
                "url": "http://example.com/phish",
                "ip": "8.8.8.8",
                "asn": "AS15169",
                "countrycode": "US",
                "countryname": "United States",
                "date": "2024-01-01",
                "title": "Fake Login Page",
            }
        ]
        return patch(
            "requests.get",
            return_value=MockUpResponse(
                mock_json_response,
                200,
                url="https://api.phishstats.info/api/phishing",
            ),
        )

    def _make_analyzer(self, observable_type, observable_value):
        analyzer = PhishStats.__new__(PhishStats)
        analyzer.observable_classification = observable_type
        analyzer.observable_name = observable_value
        return analyzer

    @patch("api_app.analyzers_manager.observable_analyzers.phishstats.requests.get")
    def test_url_observable_uses_domain_filter(self, mock_get):
        mock_get.return_value = MagicMock()
        mock_get.return_value.url = "https://api.phishstats.info/api/phishing"
        mock_get.return_value.json.return_value = []

        analyzer = self._make_analyzer(
            Classification.URL, "https://example.com/login"
        )
        result = analyzer.run()

        mock_get.assert_called_once_with(
            "https://api.phishstats.info/api/phishing",
            params={
                "_where": "(url,like,~example.com~)",
                "_sort": "-date",
            },
            timeout=30,
        )
        self.assertEqual(result["results"], [])

    @patch("api_app.analyzers_manager.observable_analyzers.phishstats.requests.get")
    def test_ip_url_uses_ip_filter(self, mock_get):
        mock_get.return_value = MagicMock()
        mock_get.return_value.url = "https://api.phishstats.info/api/phishing"
        mock_get.return_value.json.return_value = []

        analyzer = self._make_analyzer(
            Classification.URL, "https://8.8.8.8/login"
        )
        analyzer.run()

        self.assertEqual(
            mock_get.call_args.kwargs["params"]["_where"],
            "(ip,eq,8.8.8.8)",
        )

    def test_invalid_url_raises_exception(self):
        analyzer = self._make_analyzer(Classification.URL, "not-a-valid-url")

        with self.assertRaises(AnalyzerRunException):
            analyzer.run()
