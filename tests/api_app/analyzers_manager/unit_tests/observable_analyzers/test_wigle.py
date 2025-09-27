from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.wigle import WiGLE
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class WiGLETestCase(BaseAnalyzerTest):
    analyzer_class = WiGLE

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "success": True,
            "results": [
                {
                    "ssid": "TestWiFi",
                    "bssid": "00:11:22:33:44:55",
                    "trilat": 37.7749,
                    "trilong": -122.4194,
                }
            ],
        }
        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "dGVzdDp0ZXN0",  # base64 'test:test'
            "search_type": "WiFi Network",
        }
