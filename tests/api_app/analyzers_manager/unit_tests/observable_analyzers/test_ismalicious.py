# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
from copy import deepcopy
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

import requests
from django.test import TestCase as DjangoTestCase
from django.test import override_settings

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.analyzers_manager.observable_analyzers.ismalicious import (
    DEFAULT_API_URL,
    USER_AGENT,
    IsMalicious,
    check_indicator,
)
from api_app.models import Job, PluginConfig
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
INVALID_API_URLS = [
    "https://intelowl.com",
    "https://attacker.example",
    "http://api.ismalicious.com",
    "https://api.ismalicious.com.attacker.example",
    "https://api.ismalicious.com@attacker.example",
    "https://attacker.example@api.ismalicious.com",
    "https://api.ismalicious.com:444",
    "https://api.ismalicious.com/other-path",
    "https://api.ismalicious.com?redirect=attacker.example",
    "https://api.ismalicious.com#fragment",
]


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
            with (
                self.subTest(report=report),
                patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
                    return_value=self.make_response(report=report),
                ),
            ):
                self.assertEqual(check_indicator("example.com", "synthetic-credential"), report)

    def test_http_failures_are_explicit(self):
        for status_code in [401, 403, 429, 500, 503]:
            with (
                self.subTest(status_code=status_code),
                patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
                    return_value=self.make_response(status_code, {"error": "upstream failure"}),
                ),
                self.assertRaises(AnalyzerRunException),
            ):
                check_indicator("example.com", "synthetic-credential")

    def test_redirects_are_explicit_failures(self):
        for status_code in [301, 302, 307, 308]:
            with (
                self.subTest(status_code=status_code),
                patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
                    return_value=self.make_response(status_code, SAMPLE_REPORT),
                ) as mocked_get,
            ):
                with self.assertRaisesRegex(AnalyzerRunException, "redirect"):
                    check_indicator("example.com", "synthetic-credential")
                self.assertFalse(mocked_get.call_args.kwargs["allow_redirects"])

    def test_quota_refusal_preserves_the_api_message_and_next_step(self):
        message = "Monthly request quota reached. Resets on 2026-11-01."
        url = "https://ismalicious.com/pricing"
        cases = [
            ({"message": message, "cta": {"url": url}}, f"{message} {url}"),
            ({"message": f"{message} {url}", "cta": {"url": url}}, f"{message} {url}"),
            ({"error": "Payment on hold"}, "Payment on hold"),
            ({"message": message, "cta": None}, message),
            ({"message": message, "cta": {"url": 1}}, message),
            ({}, "Rate limit exceeded"),
            ({"message": {"unexpected": True}}, "Rate limit exceeded"),
            ([], "Rate limit exceeded"),
        ]
        for report, expected in cases:
            with (
                self.subTest(report=report),
                patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
                    return_value=self.make_response(429, report),
                ),
            ):
                with self.assertRaises(AnalyzerRunException) as raised:
                    check_indicator("example.com", "synthetic-credential")
                self.assertEqual(str(raised.exception), expected)

    def test_non_json_quota_refusal_remains_an_explicit_failure(self):
        with (
            patch(
                "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
                return_value=self.make_response(429, content=b"not JSON"),
            ),
            self.assertRaisesRegex(AnalyzerRunException, "Rate limit exceeded"),
        ):
            check_indicator("example.com", "synthetic-credential")

    def test_network_failures_are_explicit(self):
        for error in [requests.Timeout("timed out"), requests.ConnectionError("connection failed")]:
            with (
                self.subTest(error=type(error).__name__),
                patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
                    side_effect=error,
                ),
                self.assertRaises(AnalyzerRunException),
            ):
                check_indicator("example.com", "synthetic-credential")

    def test_invalid_json_is_an_explicit_failure(self):
        with (
            patch(
                "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
                return_value=self.make_response(content=b"not JSON"),
            ),
            self.assertRaises(AnalyzerRunException),
        ):
            check_indicator("example.com", "synthetic-credential")

    def test_invalid_response_shapes_are_explicit_failures(self):
        for report in [None, [], [SAMPLE_REPORT], "unexpected", 1, True, {}]:
            with (
                self.subTest(report=report),
                patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
                    return_value=self.make_response(report=report),
                ),
                self.assertRaisesRegex(AnalyzerRunException, "non-empty JSON object"),
            ):
                check_indicator("example.com", "synthetic-credential")

    def test_missing_input_is_rejected_before_network_io(self):
        for query, credential in [
            ("", "synthetic-credential"),
            ("   ", "synthetic-credential"),
            ("example.com", ""),
        ]:
            with (
                self.subTest(query=query, credential=credential),
                patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get"
                ) as mocked_get,
            ):
                with self.assertRaises(ValueError):
                    check_indicator(query, credential)
                mocked_get.assert_not_called()

    def test_invalid_destination_is_rejected_before_network_io(self):
        for api_url in [*INVALID_API_URLS, None]:
            with (
                self.subTest(api_url=api_url),
                patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get"
                ) as mocked_get,
            ):
                with self.assertRaisesRegex(AnalyzerRunException, "must target"):
                    check_indicator("example.com", "synthetic-credential", api_url=api_url)
                mocked_get.assert_not_called()


@override_settings(STAGE_CI=True, MOCK_CONNECTIONS=True)
class IsMaliciousConfigurationTestCase(DjangoTestCase):
    @staticmethod
    def configured_analyzer(runtime_configuration):
        config = AnalyzerConfig.objects.get(name="IsMalicious")
        analyzer = IsMalicious(config)
        analyzer._job = SimpleNamespace(
            user=None,
            is_sample=False,
            analyzable=SimpleNamespace(name="example.com", classification="domain"),
        )
        analyzer.config({"api_key_name": "synthetic-credential", **runtime_configuration})
        return analyzer

    def test_native_ci_configuration_resolves_official_default(self):
        analyzer = self.configured_analyzer({})
        self.assertEqual(analyzer.url, DEFAULT_API_URL)
        default = PluginConfig.objects.get(
            analyzer_config=analyzer._config,
            parameter__name="url",
            owner=None,
            for_organization=False,
        )
        self.assertEqual(default.value, DEFAULT_API_URL)
        self.assertFalse(default.parameter.is_secret)
        with patch(
            "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
            return_value=MockUpResponse(SAMPLE_REPORT, 200),
        ) as mocked_get:
            self.assertEqual(analyzer.run(), SAMPLE_REPORT)
            self.assertEqual(mocked_get.call_args.args[0], f"{DEFAULT_API_URL}/check")

    def test_native_runtime_override_cannot_send_credentials_to_another_host(self):
        for api_url in INVALID_API_URLS:
            with self.subTest(api_url=api_url):
                analyzer = self.configured_analyzer({"url": api_url})
                self.assertEqual(analyzer.url, api_url)
                with patch(
                    "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get"
                ) as mocked_get:
                    with self.assertRaisesRegex(AnalyzerRunException, "must target"):
                        analyzer.run()
                    mocked_get.assert_not_called()

    def test_missing_default_cannot_send_credentials_to_ci_placeholder(self):
        PluginConfig.objects.filter(
            analyzer_config__name="IsMalicious",
            parameter__name="url",
            owner=None,
            for_organization=False,
        ).delete()
        analyzer = self.configured_analyzer({})
        self.assertEqual(analyzer.url, "https://intelowl.com")
        with patch("api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get") as mocked_get:
            with self.assertRaisesRegex(AnalyzerRunException, "must target"):
                analyzer.run()
            mocked_get.assert_not_called()


class IsMaliciousDataModelTestCase(DjangoTestCase):
    def save_successful_report(self, classification, name, provider_report):
        config = AnalyzerConfig.objects.get(name="IsMalicious")
        observable, _ = Analyzable.objects.get_or_create(name=name, classification=classification)
        job = Job.objects.create(
            analyzable=observable,
            status=Job.STATUSES.ANALYZERS_RUNNING.value,
        )
        report = AnalyzerReport.objects.create(
            job=job,
            config=config,
            status=AnalyzerReport.STATUSES.RUNNING.value,
            task_id=str(uuid4()),
            parameters={},
        )
        analyzer = IsMalicious(config)
        analyzer._job = job
        analyzer.report = report
        analyzer.after_run_success(deepcopy(provider_report))
        report.refresh_from_db()
        self.assertEqual(report.status, AnalyzerReport.STATUSES.SUCCESS.value)
        self.assertEqual(report.report, provider_report)
        self.assertEqual(job.errors, [])
        self.assertIsNotNone(report.data_model)
        report.data_model.refresh_from_db()
        return report.data_model

    def test_success_creates_evidence_data_models_for_all_supported_observables(self):
        provider_report = {
            **SAMPLE_REPORT,
            "confidence": 35,
            "contradictions": ["reviewed-delisting"],
            "extraProviderField": {"kept": "in raw report"},
        }
        expected_evidence = {
            key: value for key, value in provider_report.items() if key != "extraProviderField"
        }
        for classification, name in [
            ("ip", "192.0.2.1"),
            ("domain", "example.com"),
            ("url", "https://example.com/path"),
        ]:
            with self.subTest(classification=classification):
                data_model = self.save_successful_report(classification, name, provider_report)
                self.assertEqual(data_model.additional_info, expected_evidence)
                self.assertIsNone(data_model.evaluation)
                self.assertEqual(data_model.reliability, 5)

    def test_unknown_safe_and_false_values_never_become_a_trusted_evaluation(self):
        reports = [
            {
                "malicious": False,
                "lookupStatus": "unknown",
                "riskScore": None,
                "confidence": None,
                "sources": [],
            },
            {
                "malicious": False,
                "lookupStatus": "safe",
                "riskScore": {"score": 0, "level": "low"},
                "confidence": 0,
                "sources": [],
                "contradictions": [],
            },
        ]
        for provider_report in reports:
            with self.subTest(lookup_status=provider_report["lookupStatus"]):
                data_model = self.save_successful_report("domain", "example.com", provider_report)
                self.assertEqual(data_model.additional_info, provider_report)
                self.assertIsNone(data_model.evaluation)
                self.assertEqual(data_model.reliability, 5)
