from unittest.mock import MagicMock, patch

from django.test import TestCase

from api_app.analyzers_manager.file_analyzers.yara_scan import YaraScan
from api_app.models import PluginConfig, PythonModule


class TestYaraAnalyzer(TestCase):
    def setUp(self):
        self.pm = PythonModule.objects.get(
            module="yara_scan.YaraScan",
            base_path="api_app.analyzers_manager.file_analyzers",
        )
        self.param = self.pm.parameters.get(name="repositories")
        self.pc = PluginConfig.objects.filter(parameter=self.param).first()
        self.ys = YaraScan(config=self.pc)

    @patch('api_app.analyzers_manager.file_analyzers.yara_scan.requests.get')
    def test_update_runs(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {
                    "name": "TestRule",
                    "yara_rule": "rule Test { condition: true }",
                    "id": 1
                }
            ],
            "next": None
        }
        mock_get.return_value = mock_response

        self.ys.url = "https://unprotect.it/api/detection_rules/"

        self.ys.update()

    def test_unprotect_url_in_config(self):
        """
        Verifies that the Unprotect URL was successfully added via migration.
        """
        self.assertIn("https://unprotect.it/api/detection_rules/", self.pc.value)
