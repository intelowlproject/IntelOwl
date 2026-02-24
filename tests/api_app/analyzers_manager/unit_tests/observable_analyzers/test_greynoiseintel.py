# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from api_app.analyzers_manager.observable_analyzers.greynoiseintel import (
    GreyNoiseAnalyzer,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class _CustomEmptyException(Exception):
    pass


class _CustomAttrException(Exception):
    def __init__(self):
        super().__init__("")
        self.status_code = 429
        self.error = "rate limit"
        self.response = {"message": "too many requests"}


class GreyNoiseIntelErrorFormattingTestCase(BaseAnalyzerTest):
    analyzer_class = GreyNoiseAnalyzer

    @classmethod
    def get_mocked_response(cls):
        return None

    def test_analyzer_on_supported_observables(self):
        self.skipTest("This test suite validates error formatting only.")

    def test_format_greynoise_error_uses_exception_message(self):
        exc = ValueError("GreyNoise says no")
        result = GreyNoiseAnalyzer._format_greynoise_error(exc, "fallback")
        self.assertEqual("GreyNoise says no", result)

    def test_format_greynoise_error_trims_whitespace_message(self):
        exc = RuntimeError("   temporary failure   ")
        result = GreyNoiseAnalyzer._format_greynoise_error(exc, "fallback")
        self.assertEqual("temporary failure", result)

    def test_format_greynoise_error_builds_details_when_empty(self):
        exc = _CustomAttrException()
        result = GreyNoiseAnalyzer._format_greynoise_error(
            exc, "Request failure from GreyNoise API"
        )
        expected_prefix = "Request failure from GreyNoise API (_CustomAttrException):"
        self.assertTrue(result.startswith(expected_prefix))
        self.assertIn("status_code", result)
        self.assertIn("error", result)
        self.assertIn("response", result)

    def test_format_greynoise_error_fallback_when_no_details(self):
        exc = _CustomEmptyException()
        result = GreyNoiseAnalyzer._format_greynoise_error(
            exc, "Rate limit error from GreyNoise API"
        )
        self.assertEqual(
            "Rate limit error from GreyNoise API (_CustomEmptyException)", result
        )
