# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from api_app.analyzers_manager.classes import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.presend_address_risk import PresendAddressRisk
from api_app.choices import Classification
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class PresendAddressRiskTestCase(BaseAnalyzerTest):
    analyzer_class = PresendAddressRisk

    mock_json_response = {
        "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "format": "evm",
        "sanctioned": False,
        "matched_lists": [],
        "lists_checked": [
            "ARB",
            "BCH",
            "BSC",
            "BSV",
            "BTG",
            "DASH",
            "ETC",
            "ETH",
            "LTC",
            "SOL",
            "TRX",
            "USDC",
            "USDT",
            "XBT",
            "XMR",
            "XRP",
            "XVG",
            "ZEC",
        ],
        "list_size": 1060,
        "source": "OFAC Specially Designated Nationals (SDN) list, digital currency addresses (all per-asset lists), republished nightly by 0xB10C/ofac-sanctioned-digital-currency-addresses from the official sdn_advanced.xml.",
        "note": "Not on any OFAC SDN digital currency address list. This is one specific, US-government sanctions list -- not a full risk score, and a clean result here does not mean the address is otherwise trustworthy.",
    }

    @staticmethod
    def get_mocked_response():
        mock_json_response = PresendAddressRiskTestCase.mock_json_response

        return patch(
            "requests.get",
            return_value=MockUpResponse(mock_json_response, 200),
        )

    def test_valid_evm_address(self):
        """Test that a valid EVM address passes without raising an exception"""
        with self.get_mocked_response():
            analyzer = self.analyzer_class(None)
            analyzer.observable_name = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
            analyzer.observable_classification = Classification.GENERIC
            result = analyzer.run()
            self.assertEqual(result["address"], self.mock_json_response["address"])

    def test_request_has_timeout(self):
        """Test that the HTTP request is sent with a timeout"""
        with self.get_mocked_response() as mocked_get:
            analyzer = self.analyzer_class(None)
            analyzer.observable_name = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
            analyzer.observable_classification = Classification.GENERIC
            analyzer.run()
            self.assertEqual(mocked_get.call_args.kwargs["timeout"], 10)

    def test_invalid_evm_address(self):
        """Test that an invalid EVM address raises an AnalyzerRunException"""
        analyzer = self.analyzer_class(None)
        analyzer.observable_name = "C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
        analyzer.observable_classification = Classification.GENERIC
        with self.assertRaises(AnalyzerRunException):
            analyzer.run()
