from unittest.mock import MagicMock, patch

from django.test import TestCase

from api_app.analyzers_manager.observable_analyzers.leakix import LeakIX


class TestLeakIX(TestCase):
    def setUp(self):
        self.analyzer = LeakIX()
        self.analyzer.observable_name = "1.1.1.1"
        self.analyzer.set_config({})

    @patch("requests.get")
    def test_leakix_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip": "1.1.1.1",
            "services": [{"port": 80, "protocol": "http"}],
            "leaks": [],
        }
        mock_get.return_value = mock_response

        report = self.analyzer.run()
        self.assertEqual(report["ip"], "1.1.1.1")
        self.assertEqual(len(report["services"]), 1)

    @patch("requests.get")
    def test_leakix_not_found(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        report = self.analyzer.run()
        self.assertEqual(report["status"], "not_found")
