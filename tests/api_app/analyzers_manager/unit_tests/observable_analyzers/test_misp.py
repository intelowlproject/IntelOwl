import unittest
from unittest.mock import patch

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.misp import MISP
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockResponseNoOp


class MISPTestCase(BaseAnalyzerTest):
    analyzer_class = MISP

    @staticmethod
    def get_mocked_response():
        return patch("pymisp.PyMISP", return_value=MockResponseNoOp({"response": "mocked"}, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "test_api_key",
            "_url_key_name": "https://misp.local",
            "ssl_check": False,
            "self_signed_certificate": False,
            "debug": False,
            "from_days": 30,
            "limit": 10,
            "enforce_warninglist": False,
            "filter_on_type": True,
            "strict_search": False,
            "published": True,
            "metadata": False,
        }

    def test_restsearch_get_post_error(self):
        from api_app.analyzers_manager.models import AnalyzerConfig

        configs = AnalyzerConfig.objects.filter(python_module=self.analyzer_class.python_module)
        if not configs.exists():
            self.skipTest("No AnalyzerConfig found")

        config = configs.first()
        mock_pymisp = unittest.mock.MagicMock()
        mock_pymisp.search.return_value = {
            "errors": [
                "(400, {'name': 'restSearch queries using GET and no parameters"
                " are not allowed. If you have passed parameters via a JSON body,"
                " make sure you use POST requests.', 'url': '/events/restSearch'})"
            ]
        }
        mock_pymisp.servers.getVersion.return_value = {"version": "2.4.180"}

        with patch("pymisp.PyMISP", return_value=mock_pymisp):
            analyzer = self._setup_analyzer(config, "ip", "8.8.8.8")
            with self.assertRaises(AnalyzerRunException) as context:
                analyzer.run()
            self.assertIn("GET/POST mismatch", str(context.exception))
            self.assertIn("https://", str(context.exception))

    def test_restsearch_get_post_error_debug(self):
        """Test that debug information is included in error message when debug mode is enabled."""
        from api_app.analyzers_manager.models import AnalyzerConfig

        configs = AnalyzerConfig.objects.filter(python_module=self.analyzer_class.python_module)
        if not configs.exists():
            self.skipTest("No AnalyzerConfig found")

        config = configs.first()
        mock_pymisp = unittest.mock.MagicMock()
        mock_pymisp.search.return_value = {
            "errors": [
                "(400, {'name': 'restSearch queries using GET and no parameters"
                " are not allowed. If you have passed parameters via a JSON body,"
                " make sure you use POST requests.', 'url': '/events/restSearch'})"
            ]
        }
        mock_pymisp.servers.getVersion.return_value = {"version": "2.4.180"}

        with (
            patch("pymisp.PyMISP", return_value=mock_pymisp),
            patch.object(
                self.__class__,
                "get_extra_config",
                return_value={**self.get_extra_config(), "debug": True},
            ),
        ):
            analyzer = self._setup_analyzer(config, "ip", "8.8.8.8")
            with self.assertRaises(AnalyzerRunException) as context:
                analyzer.run()

            error_message = str(context.exception)
            self.assertIn("GET/POST mismatch", error_message)
            self.assertIn("https://", error_message)
            self.assertIn("[debug:", error_message)
            self.assertIn("PyMISP version=", error_message)
            self.assertIn("ssl_check=", error_message)
