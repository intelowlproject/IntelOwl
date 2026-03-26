"""
Unit tests for the FullHunt analyzer.
"""

from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.fullhunt import FullHunt
from tests.api_app.analyzers_manager.observable_analyzers.test_quad9 import (
    ObservableAnalyzerTestCase,
)


class FullHuntTestCase(ObservableAnalyzerTestCase):
    """
    Test case for the FullHunt analyzer.
    """

    analyzer_class = FullHunt

    def test_analyzer_on_supported_observables(self):
        # This checks if the analyzer correctly identifies it supports 'domain'
        self.assertIn("domain", self.analyzer_class.supported_observables)

    @patch("api_app.analyzers_manager.classes.ObservableAnalyzer.http_get")
    def test_run_success(self, mock_get):
        # setup the fake (mock) response from FullHunt API
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "hosts": ["www.example.com"],
            "metadata": {"total_results": 1},
        }

        # initialized the analyzer with a fake config
        analyzer = self.analyzer_class(
            observable_name="example.com",
            observable_type="domain",
            config={"api_key": "fake_key"},
        )

        # Running the analyzer
        results = analyzer.run()

        # verified the output
        self.assertEqual(results["metadata"]["total_results"], 1)
        self.assertIn("www.example.com", results["hosts"])
        mock_get.assert_called_once()

    @patch("api_app.analyzers_manager.classes.ObservableAnalyzer.http_get")
    def test_run_no_data(self, mock_get):
        # code handles a 404 (No data found)
        mock_get.return_value.status_code = 404

        analyzer = self.analyzer_class(
            observable_name="nonexistent.com",
            observable_type="domain",
            config={"api_key": "fake_key"},
        )

        results = analyzer.run()
        self.assertEqual(results["status"], "empty")
        self.assertEqual(results["message"], "No data found for this domain.")
