from django.test import TestCase

from api_app.analyzers_manager.classes import AnalyzerRunException
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.analyzers_manager.observable_analyzers.nvd_cve import NVDDetails


class NVDCVETestCase(TestCase):
    config = AnalyzerConfig.objects.get(python_module=NVDDetails.python_module)

    def test_valid_cve_format(self):
        """Test that a valid CVE format passes without raising an exception"""

        analyzer = NVDDetails(self.config)
        analyzer.observable_name = "cve-2024-51181"  # Valid format

        try:
            analyzer.run()
        except AnalyzerRunException:
            self.fail("AnalyzerRunException raised with valid CVE format")

    def test_invalid_cve_format(self):
        """Test that an invalid CVE format raises an AnalyzerRunException"""
        analyzer = NVDDetails(self.config)
        analyzer.observable_name = "2024-51181"  # Invalid format

        with self.assertRaises(AnalyzerRunException):
            analyzer.run()
