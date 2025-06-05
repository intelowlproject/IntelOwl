from unittest import TestCase

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import AnalyzerConfig
from tests.api_app.analyzers_manager.unit_tests.analyzer_mocks import ANALYZER_PATCHES


class BaseAnalyzerTest(TestCase):
    analyzer_class = None
    mock_patch_key = None

    @classmethod
    def get_sample_observable(self, observable_type):
        mapping = {
            "domain": "example.com",
            "ip": "8.8.8.8",
            "url": "https://example.com",
            "hash": "deadbeefdeadbeefdeadbeefdeadbeef",
        }
        return mapping.get(observable_type, "test")

    def test_analyzer_process(self):
        if self.analyzer_class is None or self.mock_patch_key is None:
            self.skipTest("analyzer_class or mock_patch_key is not set")

        config = AnalyzerConfig.objects.get(
            python_module=self.analyzer_class.python_module
        )

        patch_context = ANALYZER_PATCHES.get(self.mock_patch_key)
        assert patch_context is not None, f"Patch for {self.mock_patch_key} not found"

        with patch_context():
            for observable_type in config.observable_supported:
                if observable_type == "generic":
                    continue
                with self.subTest(observable_type=observable_type):
                    print(f"Testing observable_type: {observable_type}")
                    observable_value = self.get_sample_observable(observable_type)
                    analyzer = self.analyzer_class(config)
                    analyzer.observable_name = observable_value
                    analyzer.observable_classification = observable_type
                    try:
                        response = analyzer.run()
                    except AnalyzerRunException:
                        self.fail("AnalyzerRunException raised with valid format")

                    # 💡 Add assertion for non-empty JSON response
                    self.assertIsInstance(
                        response,
                        dict,
                        "Analyzer response should be a dictionary (JSON object)",
                    )
                    self.assertTrue(response, "Analyzer response should not be empty")
