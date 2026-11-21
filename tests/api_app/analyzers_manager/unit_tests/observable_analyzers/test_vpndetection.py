# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Unit tests for the VPNDetection observable analyzer."""

from unittest.mock import patch

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.vpndetection import VPNDetection
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse

# Shapes copied from live responses of https://api.vpndetection.io/<ip> (2026-11-20).
VPN = {
    "ip": "146.70.116.130",
    "is_bogon": False,
    "is_vpn": True,
    "is_relay": False,
    "is_tor": False,
    "is_anycast": False,
    "relay": {},
    "tor": {},
    "location": {"continent": "EU", "country": "AT", "country_name": "Austria"},
    "asn": {
        "asn": 9009,
        "name": "M247 Europe SRL",
        "domain": "m247global.com",
        "type": "hosting",
        "prefix": "146.70.116.0/24",
        "country": "RO",
    },
    "hostname": "",
}
TOR = dict(
    VPN,
    ip="185.220.101.1",
    is_vpn=False,
    is_tor=True,
    location={"continent": "EU", "country": "DE", "country_name": "Germany"},
    asn={"asn": 60729, "name": "Stiftung Erneuerbare Freiheit", "type": "hosting"},
)
CLEAN = dict(
    VPN,
    ip="8.8.8.8",
    is_vpn=False,
    location={"continent": "NA", "country": "US", "country_name": "United States"},
    asn={"asn": 15169, "name": "Google LLC", "type": "hosting"},
)


class VPNDetectionTestCase(BaseAnalyzerTest):
    analyzer_class = VPNDetection

    @staticmethod
    def get_mocked_response():
        return patch("requests.get", return_value=MockUpResponse(VPN, 200))

    # The base class only asserts that a run returns a non-empty object. These
    # cover the request and the data model.

    @staticmethod
    def _analyzer(observable_name, api_key=""):
        analyzer = VPNDetection(config={})
        analyzer.observable_name = observable_name
        analyzer._api_key_name = api_key
        return analyzer

    @patch("requests.get", return_value=MockUpResponse(VPN, 200))
    def test_no_key_sends_no_authorization(self, mock_get):
        self.assertEqual(self._analyzer("146.70.116.130").run(), VPN)
        self.assertEqual(mock_get.call_args.args[0], "https://api.vpndetection.io/146.70.116.130")
        self.assertNotIn("Authorization", mock_get.call_args.kwargs["headers"])

    @patch("requests.get", return_value=MockUpResponse(VPN, 200))
    def test_a_key_is_sent_as_bearer(self, mock_get):
        self._analyzer("146.70.116.130", "secret").run()
        self.assertEqual(mock_get.call_args.kwargs["headers"]["Authorization"], "Bearer secret")

    @patch("requests.get", return_value=MockUpResponse({"error": "invalid API key"}, 401))
    def test_an_error_answer_raises_with_its_message(self, mock_get):
        with self.assertRaisesRegex(AnalyzerRunException, "HTTP 401: invalid API key"):
            self._analyzer("8.8.8.8", "bad").run()

    # --- data model -------------------------------------------------------

    class _Report:
        def __init__(self, report):
            self.report = report

    class _DataModel:
        def __init__(self):
            self.tags = None
            self.asn = None
            self.org_name = None
            self.country_code = None
            self.additional_info = {}

    def _creates(self, report):
        analyzer = self._analyzer(report["ip"])
        analyzer.report = self._Report(report)
        with patch.object(ObservableAnalyzer, "_do_create_data_model", lambda *a, **k: True):
            return analyzer._do_create_data_model()

    def _mapped(self, report):
        analyzer = self._analyzer(report["ip"])
        analyzer.report = self._Report(report)
        data_model = self._DataModel()
        with patch.object(ObservableAnalyzer, "_update_data_model", lambda *a, **k: None):
            analyzer._update_data_model(data_model)
        return data_model

    def test_no_flag_creates_no_data_model(self):
        self.assertFalse(self._creates(CLEAN))

    def test_a_vpn_is_an_anonymizer(self):
        self.assertTrue(self._creates(VPN))
        dm = self._mapped(VPN)
        self.assertEqual(dm.tags, ["anonymizer"])
        self.assertEqual((dm.asn, dm.org_name, dm.country_code), (9009, "M247 Europe SRL", "AT"))
        self.assertTrue(dm.additional_info["is_vpn"])

    def test_tor_is_tagged(self):
        self.assertTrue(self._creates(TOR))
        self.assertEqual(self._mapped(TOR).tags, ["anonymizer", "tor_exit_node"])

    def test_a_paid_proxy_flag_and_the_provider_reach_additional_info(self):
        report = dict(CLEAN, is_resproxy=True, vpn={"provider_name": "Mullvad"})
        self.assertTrue(self._creates(report))
        info = self._mapped(report).additional_info
        self.assertTrue(info["is_resproxy"])
        self.assertEqual(info["vpn_provider"], "Mullvad")
