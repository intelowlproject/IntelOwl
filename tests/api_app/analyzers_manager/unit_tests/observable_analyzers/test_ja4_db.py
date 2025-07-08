from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.ja4_db import Ja4DB
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class Ja4DBTestCase(BaseAnalyzerTest):
    analyzer_class = Ja4DB

    @staticmethod
    def get_mocked_response():
        sample_data = [
            {
                "application": "Nmap",
                "library": None,
                "device": None,
                "os": None,
                "user_agent_string": None,
                "certificate_authority": None,
                "observation_count": 1,
                "verified": True,
                "notes": "",
                "ja4_fingerprint": None,
                "ja4_fingerprint_string": None,
                "ja4s_fingerprint": None,
                "ja4h_fingerprint": None,
                "ja4x_fingerprint": None,
                "ja4t_fingerprint": "1024_2_1460_00",
                "ja4ts_fingerprint": None,
                "ja4tscan_fingerprint": None,
            },
            {
                "application": "Chrome",
                "library": None,
                "device": None,
                "os": "Windows",
                "user_agent_string": "Mozilla/5.0...",
                "certificate_authority": None,
                "observation_count": 1,
                "verified": False,
                "notes": None,
                "ja4_fingerprint": "t13d1517h2_8daaf6152771_b0da82dd1658",
                "ja4_fingerprint_string": "t13d1517h2_...",
                "ja4s_fingerprint": None,
                "ja4h_fingerprint": "ge11cn20enus_60ca1bd65281_ac95b44401d9_8df6a44f726c",
                "ja4x_fingerprint": None,
                "ja4t_fingerprint": None,
                "ja4ts_fingerprint": None,
                "ja4tscan_fingerprint": None,
            },
        ]
        return patch("requests.get", return_value=MockUpResponse(sample_data, 200))
