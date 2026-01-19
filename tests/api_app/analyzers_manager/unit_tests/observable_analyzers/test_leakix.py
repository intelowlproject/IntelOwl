from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.leakix import LeakIx
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class LeakIxTestCase(BaseAnalyzerTest):
    analyzer_class = LeakIx

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "Leaks": None,
            "Services": [
                {
                    "ip": "78.47.222.185",
                    "port": "22",
                    "protocol": "ssh",
                    "geoip": {
                        "country_name": "Germany",
                        "city_name": "Hachenburg",
                    },
                    "network": {
                        "organization_name": "Hetzner Online GmbH",
                        "asn": 24940,
                    },
                    "event_type": "service",
                }
            ],
        }

        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key": "test_api_key"}
