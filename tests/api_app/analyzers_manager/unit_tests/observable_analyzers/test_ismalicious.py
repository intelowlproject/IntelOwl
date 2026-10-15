# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
from unittest import TestCase
from unittest.mock import patch

import requests

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.analyzers_manager.observable_analyzers.ismalicious import (
    DEFAULT_API_URL,
    USER_AGENT,
    IsMalicious,
    check_indicator,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse

# Synthetic contract fixture, not a live verdict for the sample observables.
# Categories live on each source row in a /check response (enrichment=standard).
SAMPLE_REPORT = {
    "enrichmentLevel": "standard",
    "malicious": True,
    "riskScore": {"score": 80, "level": "critical"},
    "classification": {"primary": "c2"},
    "sources": [{"name": "feed-a", "category": "c2"}],
    "reputation": {"malicious": 1, "suspicious": 0, "harmless": 0, "undetected": 0},
}


class IsMaliciousTestCase(BaseAnalyzerTest):
    analyzer_class = IsMalicious

    @staticmethod
    def get_mocked_response():
        return patch(
            "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
            return_value=MockUpResponse(SAMPLE_REPORT, 200),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "fake_api_key"}

    def test_migration_registers_analyzer_and_secret(self):
        config = AnalyzerConfig.objects.get(name="IsMalicious")
        self.assertEqual(config.python_module.module, "ismalicious.IsMalicious")
        self.assertCountEqual(config.observable_supported, ["ip", "domain", "url"])
        parameter = config.parameters.get(name="api_key_name")
        self.assertTrue(parameter.is_secret)
        self.assertTrue(parameter.required)


class IsMaliciousContractTestCase(TestCase):
    @staticmethod
    def make_response(status_code=200, report=None, content=None):
        response = requests.Response()
        response.status_code = status_code
        response.url = f"{DEFAULT_API_URL}/check"
        response._content = content if content is not None else json.dumps(report).encode("utf-8")
        return response

    def test_preserves_query_authentication_and_request_limits(self):
        query = "https://example.com/path?a=1&b=two#fragment"
        with patch(
            "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
            return_value=self.make_response(report=SAMPLE_REPORT),
        ) as mocked_get:
            self.assertEqual(check_indicator(f"  {query}  ", "synthetic-encoded-credential"), SAMPLE_REPORT)
        mocked_get.assert_called_once_with(
            f"{DEFAULT_API_URL}/check",
            params={"query": query, "enrichment": "standard"},
            headers={
                "X-API-KEY": "synthetic-encoded-credential",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            timeout=30,
            allow_redirects=False,
        )

    def test_preserves_evidence_unknown_status_and_independent_scores(self):
        reports = [
            {**SAMPLE_REPORT, "confidence": 35, "contradictions": ["reviewed-delisting"]},
            {
                "malicious": False,
                "lookupStatus": "unknown",
                "riskScore": None,
                "confidence": None,
                "sources": [],
            },
        ]
        for report in reports:
            with self.subTest(report=report):
                with patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
                    return_value=self.make_response(report=report),
                ):
                    self.assertEqual(check_indicator("example.com", "synthetic-credential"), report)

    def test_http_failures_are_explicit(self):
        for status_code in [401, 403, 429, 500, 503]:
            with self.subTest(status_code=status_code):
                with patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
                    return_value=self.make_response(status_code, {"error": "upstream failure"}),
                ):
                    with self.assertRaises(AnalyzerRunException):
                        check_indicator("example.com", "synthetic-credential")

    def test_redirects_are_explicit_failures(self):
        for status_code in [301, 302, 307, 308]:
            with self.subTest(status_code=status_code):
                with patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
                    return_value=self.make_response(status_code, SAMPLE_REPORT),
                ) as mocked_get:
                    with self.assertRaisesRegex(AnalyzerRunException, "redirect"):
                        check_indicator("example.com", "synthetic-credential")
                    self.assertFalse(mocked_get.call_args.kwargs["allow_redirects"])

    def test_network_failures_are_explicit(self):
        for error in [requests.Timeout("timed out"), requests.ConnectionError("connection failed")]:
            with self.subTest(error=type(error).__name__):
                with patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
                    side_effect=error,
                ):
                    with self.assertRaises(AnalyzerRunException):
                        check_indicator("example.com", "synthetic-credential")

    def test_invalid_json_is_an_explicit_failure(self):
        with patch(
            "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
            return_value=self.make_response(content=b"not JSON"),
        ):
            with self.assertRaises(AnalyzerRunException):
                check_indicator("example.com", "synthetic-credential")

    def test_invalid_response_shapes_are_explicit_failures(self):
        for report in [None, [], [SAMPLE_REPORT], "unexpected", 1, True, {}]:
            with self.subTest(report=report):
                with patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
                    return_value=self.make_response(report=report),
                ):
                    with self.assertRaisesRegex(AnalyzerRunException, "non-empty JSON object"):
                        check_indicator("example.com", "synthetic-credential")

    def test_missing_input_is_rejected_before_network_io(self):
        for query, credential in [
            ("", "synthetic-credential"),
            ("   ", "synthetic-credential"),
            ("example.com", ""),
        ]:
            with self.subTest(query=query, credential=credential):
                with patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get"
                ) as mocked_get:
                    with self.assertRaises(ValueError):
                        check_indicator(query, credential)
                    mocked_get.assert_not_called()
