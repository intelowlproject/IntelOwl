from types import SimpleNamespace
from unittest.mock import patch

from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.analyzers_manager.observable_analyzers.ip2location import Ip2location
from api_app.data_model_manager.enums import DataModelTags
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse

MOCK_RESPONSE = {
    "ip": "8.8.8.8",
    "country_code": "US",
    "country_name": "United States of America",
    "region_name": "California",
    "city_name": "Mountain View",
    "latitude": 37.405992,
    "longitude": -122.078515,
    "zip_code": "94043",
    "time_zone": "-07:00",
    "asn": "15169",
    "as": "Google LLC",
    "is_proxy": False,
    # Present on the IP2Location.io Security plan. Free and keyless responses
    # include is_proxy only.
    "proxy": {
        "last_seen": 13,
        "proxy_type": "DCH",
        "threat": "-",
        "provider": "-",
        "is_vpn": False,
        "is_tor": False,
        "is_data_center": True,
        "is_public_proxy": False,
        "is_web_proxy": False,
        "is_residential_proxy": False,
        "is_consumer_privacy_network": False,
        "is_enterprise_private_network": False,
        "is_spammer": False,
        "is_scanner": False,
        "is_botnet": False,
        "is_bogon": False,
    },
}


class Ip2locationTestCase(BaseAnalyzerTest):
    analyzer_class = Ip2location

    @staticmethod
    def get_mocked_response():
        return patch("requests.get", return_value=MockUpResponse(MOCK_RESPONSE, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "dummy_key", "api_version": "keyed"}

    def _analyzer(self, api_version="keyless", api_key=None):
        config = AnalyzerConfig.objects.get(name="Ip2location")
        analyzer = self._setup_analyzer(config, "ip", "8.8.8.8")
        analyzer.api_version = api_version
        if api_key is None and hasattr(analyzer, "_api_key_name"):
            del analyzer._api_key_name
        elif api_key is not None:
            analyzer._api_key_name = api_key
        return analyzer

    def test_keyless_does_not_send_api_key(self):
        analyzer = self._analyzer("keyless", api_key="should-not-be-sent")
        with patch("requests.get", return_value=MockUpResponse(MOCK_RESPONSE, 200)) as mocked:
            result = analyzer.run()
        params = mocked.call_args.kwargs["params"]
        self.assertEqual(params, {"ip": "8.8.8.8"})
        self.assertNotIn("key", params)
        self.assertEqual(result["country_code"], "US")
        self.assertIn("proxy", result)

    def test_class_default_is_keyless(self):
        config = AnalyzerConfig.objects.get(name="Ip2location")
        analyzer = Ip2location(config)
        analyzer.observable_name = "8.8.8.8"
        self.assertEqual(analyzer.api_version, "keyless")
        with patch("requests.get", return_value=MockUpResponse(MOCK_RESPONSE, 200)) as mocked:
            analyzer.run()
        self.assertNotIn("key", mocked.call_args.kwargs["params"])

    def test_keyed_sends_api_key(self):
        analyzer = self._analyzer("keyed", api_key="real-key")
        with patch("requests.get", return_value=MockUpResponse(MOCK_RESPONSE, 200)) as mocked:
            analyzer.run()
        self.assertEqual(
            mocked.call_args.kwargs["params"],
            {"ip": "8.8.8.8", "key": "real-key"},
        )

    def test_keyed_without_key_fails(self):
        analyzer = self._analyzer("keyed", api_key=None)
        with self.assertRaises(AnalyzerConfigurationException):
            analyzer.run()

    def test_keyed_with_whitespace_key_fails(self):
        for blank in ("", " ", "   ", "\t\n"):
            with self.subTest(key=repr(blank)):
                analyzer = self._analyzer("keyed", api_key=blank)
                with (
                    patch("requests.get") as mocked,
                    self.assertRaises(AnalyzerConfigurationException),
                ):
                    analyzer.run()
                mocked.assert_not_called()

    def test_keyed_strips_surrounding_whitespace(self):
        analyzer = self._analyzer("keyed", api_key="  real-key \n")
        with patch("requests.get", return_value=MockUpResponse(MOCK_RESPONSE, 200)) as mocked:
            analyzer.run()
        self.assertEqual(
            mocked.call_args.kwargs["params"],
            {"ip": "8.8.8.8", "key": "real-key"},
        )

    def test_proxy_flags_map_into_the_data_model(self):
        analyzer = self._analyzer()
        analyzer.report = SimpleNamespace(
            report={
                "country_code": "US",
                "asn": "15169",
                "as": "Google LLC",
                "is_proxy": True,
                "proxy": {
                    "proxy_type": "TOR",
                    "is_tor": True,
                    "is_vpn": False,
                    "is_scanner": True,
                    "provider": "Example",
                },
            }
        )
        data_model = SimpleNamespace(tags=None, additional_info=None, asn=None)
        analyzer._update_data_model(data_model)
        self.assertEqual(data_model.asn, 15169)
        self.assertIn(DataModelTags.ANONYMIZER.value, data_model.tags)
        self.assertIn(DataModelTags.TOR_EXIT_NODE.value, data_model.tags)
        self.assertIn(DataModelTags.SCANNER.value, data_model.tags)
        self.assertTrue(data_model.additional_info["is_proxy"])
        self.assertEqual(data_model.additional_info["proxy"]["provider"], "Example")

    def test_basic_is_proxy_without_security_fields(self):
        analyzer = self._analyzer()
        analyzer.report = SimpleNamespace(
            report={"asn": "-", "is_proxy": False},
        )
        data_model = SimpleNamespace(tags=[], additional_info={}, asn=None)
        analyzer._update_data_model(data_model)
        self.assertIsNone(data_model.asn)
        self.assertEqual(data_model.tags, [])
        self.assertEqual(data_model.additional_info, {"is_proxy": False})
        self.assertNotIn("proxy", data_model.additional_info)
