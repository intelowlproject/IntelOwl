from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.mnemonic_pdns import (
    MnemonicPassiveDNS,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class MnemonicPassiveDNSTestCase(BaseAnalyzerTest):
    analyzer_class = MnemonicPassiveDNS

    @staticmethod
    def get_mocked_response():
        # This covers both JSON and COF response modes
        json_response = {
            "passive_dns": [
                {
                    "rrtype": "A",
                    "rdata": "1.2.3.4",
                    "time_first": "2023-01-01T00:00:00Z",
                    "time_last": "2023-01-02T00:00:00Z",
                }
            ]
        }

        cof_response = (
            '{"rrtype": "A", "rdata": "1.2.3.4", "time_first": "2023-01-01", "time_last": "2023-01-02"}\n'
            '{"rrtype": "A", "rdata": "5.6.7.8", "time_first": "2023-02-01", "time_last": "2023-02-02"}'
        )

        def side_effect(url, data=None):
            if "cof" in url:
                return MockUpResponse(cof_response, 200)
            return MockUpResponse(json_response, 200)

        return patch("requests.get", side_effect=side_effect)

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"cof_format": False, "limit": 100}
