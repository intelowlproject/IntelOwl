from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.otx import OTX
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class OTXTestCase(BaseAnalyzerTest):
    analyzer_class = OTX

    @staticmethod
    def get_mocked_response():
        # Minimal but valid mock structure for all supported sections
        mock_data = {
            "pulse_info": {"pulses": [{"id": "123", "name": "Mock Pulse"}]},
            "geo": {"country": "US"},
            "data": [{"hash": "deadbeef", "detections": {"mockAV": "malicious"}}],
            "passive_dns": [{"hostname": "example.com"}],
            "reputation": {"reputation": 85},
            "url_list": [{"url": "http://malicious.com"}],
            "analysis": {"plugins": {"some": "data"}},
        }

        return patch(
            "requests.Session.get",
            return_value=MockUpResponse(mock_data, 200),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "mock-api-key",
            "verbose": False,
            "sections": [
                "general",
                "geo",
                "malware",
                "passive_dns",
                "reputation",
                "url_list",
                "analysis",
            ],
            "full_analysis": False,
            "timeout": 10,
        }
