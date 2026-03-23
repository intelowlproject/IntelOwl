from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.criminalip.criminalip_scan import (
    CriminalIpScan,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class CriminalIpScanTestCase(BaseAnalyzerTest):
    analyzer_class = CriminalIpScan

    @staticmethod
    def get_mocked_response():
        # Mocked responses for scan, status polling, and report
        post_scan_response = {
            "status": 200,
            "data": {
                "scan_id": "scan123",
            },
        }
        get_status_response = {"data": {"scan_percentage": 100}}
        get_report_response = {"data": {"verdict": "suspicious", "details": {"score": 85}}}

        return [
            patch(
                "requests.post",
                return_value=MockUpResponse(post_scan_response, 200),
            ),
            patch(
                "requests.get",
                side_effect=[
                    MockUpResponse(get_status_response, 200),  # status endpoint
                    MockUpResponse(get_report_response, 200),  # report endpoint
                ],
            ),
        ]

    @classmethod
    def get_extra_config(cls):
        return {
            "_api_key_name": "Bearer dummykey",  # Adjust if needed
            "url": "https://dummy.criminalip.io",  # Fake base URL for testing
        }
