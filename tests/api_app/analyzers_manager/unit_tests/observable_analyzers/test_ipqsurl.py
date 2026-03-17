"""Unit tests for the IPQS URL observable analyzer."""

from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.ipqsurl import IPQSUrlScan
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers import (
    base_test_class,
)
from tests.mock_utils import MockUpResponse


class IPQSUrlScanTestCase(base_test_class.BaseAnalyzerTest):
    """Tests for the `IPQSUrlScan` observable analyzer."""

    analyzer_class = IPQSUrlScan

    @staticmethod
    def get_mocked_response():
        # Response for lookup endpoint (non-cached case)
        lookup_response = {
            "file_name": "www.google.com",
            "success": True,
            "message": "Success",
            "status": "not_cached",
            "request_id": "dxwrE9RhS3",
        }
        # Response for scan endpoint
        scan_response = {
            "file_name": "www.google.com",
            "success": True,
            "message": "Success",
            "request_id": "dxwrE9RhS3",
        }
        # Final response from poll_for_report
        final_response = {
            "file_name": "www.google.com",
            "success": True,
            "message": "Success",
            "file_hash": ("86cc9b097d5ea4ec64a086634ef0f57b864770ccd1129d"),
            "type": "scan",
            "detected": False,
            "detected_scans": 0,
            "total_scans": 0,
            "status": "finished",
            "result": [""],
            "file_size": 272728,
            "file_type": "text/html",
            "sha1": "379066b095304b84a0cc53888cda558ef483a4dd",
            "md5": "4eb7c45715293e6effd84f4894cff654",
            "request_id": "dxwrE9RhS3",
        }
        return [
            patch(
                "requests.post",
                side_effect=[
                    MockUpResponse(lookup_response, 200),
                    MockUpResponse(scan_response, 200),
                ],
            ),
            patch(
                "requests.get",
                return_value=MockUpResponse(final_response, 200),
            ),
        ]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_ipqs_api_key": "dummy_key",
            "polling_interval": 0,
            "max_retries": 1,
        }
