# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Unit tests for the InternetData observable analyzer."""

from unittest.mock import patch

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.internetdata import InternetData
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse

# Shapes copied from live responses of https://api.internetdata.io/<ip> (2026-11-25),
# trimmed of the location's currency and flag fields. With no key the answer has only
# the core fields: no is_bot, is_carrier, is_satellite, service flags or asn.type.
TOR = {
    "ip": "185.220.101.1",
    "is_bogon": False,
    "is_tor": True,
    "is_relay": False,
    "is_anycast": False,
    "location": {"continent": "EU", "country": "DE", "country_name": "Germany", "timezone": "Europe/Berlin"},
    "tor": {"provider": "", "provider_name": "", "confidence": "high", "last_seen": "2026-11-25"},
    "relay": {},
    "asn": {
        "asn": 60729,
        "name": "Stiftung Erneuerbare Freiheit",
        "domain": "zwiebelfreunde.de",
        "prefix": "185.220.101.0/24",
        "country": "DE",
        "rpki_status": "valid",
    },
    "company": {"name": "Artikel10 e.V.", "domain": "artikel10.org"},
    "hostname": "berlin01.tor-exit.artikel10.org",
    "abuse": {"email": "abuse@artikel10.org"},
}
ANYCAST = dict(
    TOR,
    ip="8.8.8.8",
    is_tor=False,
    is_anycast=True,
    location={"continent": "NA", "country": "US", "country_name": "United States"},
    tor={},
    asn={"asn": 15169, "name": "Google LLC", "domain": "google.com", "prefix": "8.8.8.0/24", "country": "US"},
    company={"name": "Google LLC", "domain": "google.com"},
    hostname="dns.google",
    abuse={"email": "network-abuse@google.com"},
)
# With a key on a paid plan: the VPN, proxy and hosting flags and their providers, and the
# bot, carrier, satellite and service flags.
VPN = dict(
    TOR,
    ip="146.70.116.130",
    is_tor=False,
    is_vpn=True,
    is_resproxy=False,
    is_dcproxy=False,
    is_mobproxy=False,
    is_pubproxy=False,
    is_hosting=True,
    is_cdn=False,
    is_bot=False,
    is_carrier=False,
    is_satellite=False,
    is_ssh=False,
    is_smtp=False,
    is_web=True,
    is_dns_resolver=False,
    is_bittorrent=False,
    location={"continent": "EU", "country": "AT", "country_name": "Austria", "city": "Vienna"},
    vpn={"provider": "mullvad", "provider_name": "Mullvad", "confidence": "high", "last_seen": "2026-11-25"},
    tor={},
    hosting={"provider": "m247", "provider_name": "M247", "confidence": "high", "last_seen": "2026-11-25"},
    asn={
        "asn": 9009,
        "name": "M247 Europe SRL",
        "domain": "m247global.com",
        "type": "hosting",
        "prefix": "146.70.116.0/24",
    },
    company={"name": "M247 LTD Vienna Infrastructure", "domain": "m247.ro", "type": "hosting"},
    hostname="",
    abuse={"email": "abuse@m247.ro", "name": "M247 Europe"},
)
BOGON = dict(
    TOR,
    ip="10.0.0.1",
    is_bogon=True,
    is_tor=False,
    location={"continent": "", "country": ""},
    tor={},
    asn={"asn": 0, "name": "", "prefix": ""},
    company={"name": "", "domain": ""},
    hostname="",
    abuse={"email": ""},
)


class InternetDataTestCase(BaseAnalyzerTest):
    analyzer_class = InternetData

    @staticmethod
    def get_mocked_response():
        return patch("requests.get", return_value=MockUpResponse(ANYCAST, 200))

    # The base class only asserts that a run returns a non-empty object. These
    # cover the request and the data model.

    @staticmethod
    def _analyzer(observable_name, api_key=""):
        analyzer = InternetData(config={})
        analyzer.observable_name = observable_name
        analyzer._api_key_name = api_key
        return analyzer

    @patch("requests.get", return_value=MockUpResponse(ANYCAST, 200))
    def test_no_key_sends_no_authorization(self, mock_get):
        self.assertEqual(self._analyzer("8.8.8.8").run(), ANYCAST)
        self.assertEqual(mock_get.call_args.args[0], "https://api.internetdata.io/8.8.8.8")
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
            self.isp = None
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

    def test_a_bogon_creates_no_data_model(self):
        self.assertFalse(self._creates(BOGON))

    def test_a_public_address_maps_its_network_with_no_tag(self):
        self.assertTrue(self._creates(ANYCAST))
        dm = self._mapped(ANYCAST)
        self.assertIsNone(dm.tags)
        self.assertEqual(
            (dm.asn, dm.org_name, dm.isp, dm.country_code), (15169, "Google LLC", "Google LLC", "US")
        )
        info = dm.additional_info
        self.assertTrue(info["is_anycast"])
        self.assertEqual(info["prefix"], "8.8.8.0/24")
        self.assertEqual(info["abuse_email"], "network-abuse@google.com")
        self.assertEqual(info["hostname"], "dns.google")

    def test_tor_is_an_anonymizer_not_an_exit_node(self):
        dm = self._mapped(TOR)
        self.assertEqual(dm.tags, ["anonymizer"])
        self.assertTrue(dm.additional_info["is_tor"])
        self.assertNotIn("is_bot", dm.additional_info)
        self.assertEqual(dm.isp, "Artikel10 e.V.")

    def test_a_paid_vpn_is_an_anonymizer_with_its_providers(self):
        dm = self._mapped(VPN)
        self.assertEqual(dm.tags, ["anonymizer"])
        info = dm.additional_info
        self.assertTrue(info["is_vpn"])
        self.assertFalse(info["is_resproxy"])
        self.assertFalse(info["is_bot"])
        self.assertFalse(info["is_carrier"])
        self.assertEqual(info["vpn_provider"], "Mullvad")
        self.assertEqual(info["hosting_provider"], "M247")
        self.assertNotIn("hostname", info)

    def test_empty_fields_map_to_none(self):
        dm = self._mapped(BOGON)
        self.assertEqual((dm.asn, dm.org_name, dm.isp, dm.country_code), (None, None, None, None))
