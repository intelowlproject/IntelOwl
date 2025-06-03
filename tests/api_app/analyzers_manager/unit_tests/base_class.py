# tests/base_analyzer_testcase.py

from unittest import TestCase

from tests.api_app.analyzers_manager.unit_tests.analyzer_mocks import ANALYZER_PATCHES


class BaseAnalyzerTestCase(TestCase):
    analyzer_class = None  # override this in subclass
    mock_patch_key = None  # override this in subclass
    observable_name = None  # override this in subclass

    def setUp(self):
        assert self.analyzer_class, "Must set analyzer_class"
        assert self.mock_patch_key, "Must set mock_patch_key"
        assert self.observable_name, "Must set observable_name"
        self.config = {}  # or build a mock config if required

    def test_run_success(self):
        patch_fn = ANALYZER_PATCHES[self.mock_patch_key]
        with patch_fn():
            analyzer = self.analyzer_class(self.config)
            analyzer.observable_name = self.observable_name
            result = analyzer.run()
            self.assertIsInstance(result, dict)
            self.assertIn("ip", result)
