# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Unit tests for the NetAPI observable analyzer."""

from unittest.mock import patch

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.netapi import NetAPI
from api_app.choices import Classification
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse

# Shapes copied from live responses of
# https://netapi.com/api-json/?method=compromised-check&value=... (2026-11-13).
LISTED_IP = {
    "value": "1.0.166.69",
    "type": "ip",
    "listed_now": True,
    "listed_ever": True,
    "matched_value": "1.0.166.69",
    "first_seen": "2026-11-03",
    "last_seen": "2026-11-13 05:36:10 UTC",
    "block_reason": "NetAPI network sensors: service exploit",
    "registrar": None,
    "note": "Seen in the compromised feed within the last 48 hours.",
    "lists": {
        "page": "https://netapi.com/compromised-ips/",
        "current": "https://netapi.com/api2/?method=compromised&dataset_type=ip",
        "all_time": "https://netapi.com/api2/?method=compromised&dataset_type=ip-all",
    },
    "source": "NetAPI Nightwatch compromised IP feed, updated hourly (CC BY 4.0)",
}
LISTED_BEFORE = {
    "value": "0-07.ru",
    "type": "domain",
    "listed_now": False,
    "listed_ever": True,
    "matched_value": "0-07.ru",
    "first_seen": "2019-12-18",
    "last_seen": "2019-12-25 00:00:00 UTC",
    "block_reason": "suspicious",
    "registrar": None,
    "note": "Listed in the past but not seen in the last 24 hours; most such entries reflect past incidents only.",
    "lists": {
        "page": "https://netapi.com/compromised-urls/",
        "current": "https://netapi.com/api2/?method=compromised&dataset_type=url",
        "all_time": "https://netapi.com/api2/?method=compromised&dataset_type=url-all",
    },
    "source": "NetAPI compromised feed, updated daily (CC BY 4.0)",
}
NOT_LISTED = {
    "value": "example.com",
    "type": "domain",
    "listed_now": False,
    "listed_ever": False,
    "matched_value": None,
    "first_seen": None,
    "last_seen": None,
    "block_reason": None,
    "registrar": None,
    "note": "Not in the current or historical compromised feed.",
    "lists": {
        "page": "https://netapi.com/compromised-urls/",
        "current": "https://netapi.com/api2/?method=compromised&dataset_type=url",
        "all_time": "https://netapi.com/api2/?method=compromised&dataset_type=url-all",
    },
    "source": "NetAPI compromised feed, updated daily (CC BY 4.0)",
}


class NetAPITestCase(BaseAnalyzerTest):
    analyzer_class = NetAPI

    @staticmethod
    def get_mocked_response():
        return patch("requests.get", return_value=MockUpResponse(LISTED_IP, 200))

    # The base class only asserts that a run returns a non-empty object. These
    # cover the request and the data model.

    @staticmethod
    def _analyzer(observable_name, classification):
        analyzer = NetAPI(config={})
        analyzer.observable_name = observable_name
        analyzer.observable_classification = classification
        return analyzer

    @patch("requests.get", return_value=MockUpResponse(LISTED_IP, 200))
    def test_ip_is_sent_as_is(self, mock_get):
        result = self._analyzer("1.0.166.69", Classification.IP).run()
        self.assertEqual(result, LISTED_IP)
        params = mock_get.call_args.kwargs["params"]
        self.assertEqual(params, {"method": "compromised-check", "value": "1.0.166.69"})

    @patch("requests.get", return_value=MockUpResponse(NOT_LISTED, 200))
    def test_url_is_reduced_to_its_host(self, mock_get):
        self._analyzer("https://example.com/login?x=1", Classification.URL).run()
        self.assertEqual(mock_get.call_args.kwargs["params"]["value"], "example.com")

    def test_url_without_host_raises(self):
        with self.assertRaises(AnalyzerRunException):
            self._analyzer("not a url", Classification.URL).run()

    @patch(
        "requests.get",
        return_value=MockUpResponse(
            {"error": {"code": "invalid_value", "message": "Not a valid domain name or IP address."}},
            400,
        ),
    )
    def test_an_error_answer_raises_with_its_message(self, mock_get):
        with self.assertRaisesRegex(AnalyzerRunException, "Not a valid domain name"):
            self._analyzer("nodot", Classification.DOMAIN).run()

    @patch(
        "requests.get",
        return_value=MockUpResponse(
            {"error": {"code": "rate_limited", "message": "Too many requests: limit of 30 per minute."}},
            429,
        ),
    )
    def test_rate_limit_raises(self, mock_get):
        with self.assertRaisesRegex(AnalyzerRunException, "HTTP 429"):
            self._analyzer("example.com", Classification.DOMAIN).run()

    # --- data model -------------------------------------------------------

    class _Report:
        def __init__(self, report):
            self.report = report

    class _DataModel:
        def __init__(self):
            self.evaluation = None
            self.reliability = None
            self.additional_info = {}

    def _creates(self, report):
        analyzer = self._analyzer(report["value"], Classification.DOMAIN)
        analyzer.report = self._Report(report)
        with patch.object(ObservableAnalyzer, "_do_create_data_model", lambda *a, **k: True):
            return analyzer._do_create_data_model()

    def _mapped(self, report):
        analyzer = self._analyzer(report["value"], Classification.DOMAIN)
        analyzer.report = self._Report(report)
        data_model = self._DataModel()
        with patch.object(ObservableAnalyzer, "_update_data_model", lambda *a, **k: None):
            analyzer._update_data_model(data_model)
        return data_model

    def test_not_listed_creates_no_data_model(self):
        self.assertFalse(self._creates(NOT_LISTED))

    def test_listed_now_is_malicious(self):
        self.assertTrue(self._creates(LISTED_IP))
        dm = self._mapped(LISTED_IP)
        self.assertEqual(dm.evaluation, "malicious")
        self.assertEqual(dm.reliability, 7, "shown as malicious, not suspicious")
        self.assertEqual(dm.additional_info["block_reason"], "NetAPI network sensors: service exploit")

    def test_listed_before_is_suspicious(self):
        self.assertTrue(self._creates(LISTED_BEFORE))
        dm = self._mapped(LISTED_BEFORE)
        self.assertEqual(dm.evaluation, "malicious")
        self.assertEqual(dm.reliability, 3, "shown as suspicious")

    def test_a_listed_parent_domain_is_suspicious(self):
        report = dict(LISTED_BEFORE, value="sub.0-07.ru", listed_now=True)
        self.assertTrue(self._creates(report))
        dm = self._mapped(report)
        self.assertEqual(dm.evaluation, "malicious")
        self.assertEqual(dm.reliability, 5, "the listing is about the parent, not this host")
        self.assertEqual(dm.additional_info["matched_value"], "0-07.ru")

    def test_a_past_listing_of_a_parent_domain_creates_no_data_model(self):
        # A parent that was listed years ago says nothing about this host.
        report = dict(LISTED_BEFORE, value="sub.0-07.ru")
        self.assertFalse(self._creates(report))

    def test_www_of_a_listed_domain_is_the_domain_itself(self):
        # The feed stores domains without "www.", so the www host is the same site.
        report = dict(LISTED_BEFORE, value="www.0-07.ru", listed_now=True)
        self.assertEqual(self._mapped(report).reliability, 7, "shown as malicious, not suspicious")
        past = dict(LISTED_BEFORE, value="www.0-07.ru")
        self.assertTrue(self._creates(past))
        self.assertEqual(self._mapped(past).reliability, 3)
