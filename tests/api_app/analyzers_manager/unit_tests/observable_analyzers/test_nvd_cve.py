# from unittest.mock import patch

from api_app.analyzers_manager.classes import AnalyzerRunException
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.analyzers_manager.observable_analyzers.nvd_cve import NVDDetails
from tests.api_app.analyzers_manager.unit_tests.analyzer_mocks import ANALYZER_PATCHES
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class NVDCVETestCase(BaseAnalyzerTest):

    analyzer_class = NVDDetails
    mock_patch_key = "nvd_cve"

    config = AnalyzerConfig.objects.get(python_module=NVDDetails.python_module)

    def test_valid_cve_format(self, *args, **kwargs):
        """Test that a valid CVE format passes without raising an exception"""
        with ANALYZER_PATCHES["nvd_cve"]():

            analyzer = NVDDetails(self.config)
            analyzer.observable_name = "cve-2024-51181"

            try:
                analyzer.run()
            except AnalyzerRunException:
                self.fail("AnalyzerRunException raised with valid CVE format")

    def test_invalid_cve_format(self, *args, **kwargs):
        """Test that an invalid CVE format raises an AnalyzerRunException"""
        analyzer = NVDDetails(self.config)
        analyzer.observable_name = "2024-51181"

        with self.assertRaises(AnalyzerRunException):
            analyzer.run()
