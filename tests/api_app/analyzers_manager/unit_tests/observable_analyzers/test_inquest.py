from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.inquest import InQuest
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import BaseAnalyzerTest
from tests.mock_utils import MockUpResponse


class InQuestTestCase(BaseAnalyzerTest):
    analyzer_class = InQuest

    @staticmethod
    def get_mocked_response():
        mock_response = {"result": "ok", "data": ["some IOC result"]}
        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "inquest_analysis": "dfi_search",
            "_api_key_name": "Bearer dummy_api_key",
            "generic_identifier_mode": "user-defined",
        }


class TypeOfGenericTestCase(InQuestTestCase):
    """Tests for the type_of_generic method."""

    @classmethod
    def get_extra_config(cls) -> dict:
        config = super().get_extra_config()
        config["generic_identifier_mode"] = "auto"
        return config

    def setUp(self):
        super().setUp()
        # Create a mock analyzer config
        from api_app.analyzers_manager.models import AnalyzerConfig

        config = AnalyzerConfig.objects.filter(python_module=self.analyzer_class.python_module).first()
        if not config:
            self.skipTest(
                "AnalyzerConfig for InQuest is not available; skipping TypeOfGenericTestCase tests."
            )
        self.analyzer = self._setup_analyzer(config, "generic", "test")

    def test_type_of_generic_email_simple(self):
        self.analyzer.observable_name = "user@example.com"
        self.assertEqual(self.analyzer.type_of_generic(), "email")

    def test_type_of_generic_email_with_subdomain(self):
        self.analyzer.observable_name = "user.name+tag@sub.domain.info"
        self.assertEqual(self.analyzer.type_of_generic(), "email")

    def test_type_of_generic_email_long_tld(self):
        self.analyzer.observable_name = "test@domain.museum"
        self.assertEqual(self.analyzer.type_of_generic(), "email")

    def test_type_of_generic_registry_hkey(self):
        self.analyzer.observable_name = "HKEY_LOCAL_MACHINE\\Software\\Test"
        self.assertEqual(self.analyzer.type_of_generic(), "registry")

    def test_type_of_generic_registry_hklm(self):
        self.analyzer.observable_name = "HKLM\\Software\\Microsoft"
        self.assertEqual(self.analyzer.type_of_generic(), "registry")

    def test_type_of_generic_registry_hkcu(self):
        self.analyzer.observable_name = "HKCU\\Desktop"
        self.assertEqual(self.analyzer.type_of_generic(), "registry")

    def test_type_of_generic_xmpid(self):
        self.analyzer.observable_name = "550e8400-e29b-41d4-a716-446655440000"
        self.assertEqual(self.analyzer.type_of_generic(), "xmpid")

    def test_type_of_generic_filename_simple(self):
        self.analyzer.observable_name = "malware.exe"
        self.assertEqual(self.analyzer.type_of_generic(), "filename")

    def test_type_of_generic_filename_with_spaces(self):
        self.analyzer.observable_name = "my document.pdf"
        self.assertEqual(self.analyzer.type_of_generic(), "filename")

    def test_type_of_generic_unknown_defaults_to_filename(self):
        self.analyzer.observable_name = "random-text-no-extension"
        self.assertEqual(self.analyzer.type_of_generic(), "filename")

    @patch("api_app.analyzers_manager.observable_analyzers.inquest.logger.warning")
    def test_type_of_generic_unknown_warning(self, mock_warning):
        self.analyzer.observable_name = "random-text-no-extension"
        self.analyzer.type_of_generic()
        mock_warning.assert_called_once_with(
            "Could not determine type of generic observable: "
            "'random-text-no-extension'. Defaulting to 'filename'."
        )
