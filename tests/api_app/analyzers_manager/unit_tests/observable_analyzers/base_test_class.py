# tests/base_analyzer_testcase.py

from unittest import TestCase

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.analyzers_manager.observable_analyzers.nvd_cve import NVDDetails
from tests.api_app.analyzers_manager.unit_tests.analyzer_mocks import ANALYZER_PATCHES


class BaseAnalyzerTest(TestCase):
    analyzer_class = NVDDetails  # To be set by subclasses
    mock_patch_key = "nvd_cve"  # To be set by subclasses
    config = AnalyzerConfig.objects.get(python_module=analyzer_class.python_module)

    def get_sample_observable(self, observable_type):
        mapping = {
            "domain": "example.com",
            "ip": "8.8.8.8",
            "url": "https://example.com",
            "hash": "deadbeefdeadbeefdeadbeefdeadbeef",
            "generic": "test@intelowl.com",
        }
        return mapping.get(observable_type, "test")

    def test_analyzer_process(self):
        assert self.analyzer_class is not None, "analyzer_class is not set"
        assert self.mock_patch_key is not None, "mock_patch_key is not set"

        # Patch analyzer_patches
        # patch_data = ANALYZER_PATCHES.get(self.mock_patch_key, {})
        with ANALYZER_PATCHES[self.mock_patch_key]():
            for observable_type in self.config.observable_supported:
                with self.subTest(observable_type=observable_type):
                    observable_value = self.get_sample_observable(observable_type)
                    analyzer = self.analyzer_class(self.config)
                    analyzer.observable_name = observable_value
                    try:
                        analyzer.run()
                    except AnalyzerRunException:
                        self.fail("AnalyzerRunException raised with valid format")
