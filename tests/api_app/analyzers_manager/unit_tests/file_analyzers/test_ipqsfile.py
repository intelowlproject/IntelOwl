"""Unit tests for the IPQS file analyzer.

These tests mock IPQualityScore API interactions for file scanning.
"""

from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.ipqsfile import IPQSFileScan

from .base_test_class import BaseFileAnalyzerTest


class TestIPQSFileScan(BaseFileAnalyzerTest):
    """Tests for `IPQSFileScan` analyzer."""

    analyzer_class = IPQSFileScan

    @classmethod
    def get_extra_config(cls):
        return {
            "ipqs_api_key": "dummy_key",
        }

    @classmethod
    def get_mocked_response(cls):
        # Response for lookup endpoint (non-cached case)
        lookup_response = {
            "file_name": "test file 1234 (Copy 5).txt",
            "success": True,
            "message": "Success",
            "file_hash": ("0690f15bdb8daac1048a123deb8a33820"),
            "type": "scan",
            "detected": False,
            "detected_scans": 0,
            "total_scans": 0,
            "status": "pending",
            "result": [""],
            "file_size": 128,
            "file_type": "text/plain",
            "sha1": "3f596328e6ac7290fd29bbb90c2dfb8a4b9faea9",
            "md5": "aba7f904d8cf31dd409cd51b2bd532bb",
            "request_id": "dxyOPeUGK3",
        }

        # Response for scan endpoint
        scan_response = {
            "file_name": "test file 1234 (Copy 5).txt",
            "success": True,
            "message": "Success",
            "request_id": "dxyOPeUGK3",
        }

        # Final response from poll_for_report
        final_response = {
            "file_name": "test file 1234 (Copy 5).txt",
            "success": True,
            "message": "Success",
            "file_hash": ("0690f15bdb8daac1048a123deb8a33820"),
            "type": "scan",
            "detected": False,
            "detected_scans": 0,
            "total_scans": 0,
            "status": "finished",
            "result": [""],
            "file_size": 128,
            "file_type": "text/plain",
            "sha1": "3f596328e6ac7290fd29bbb90c2dfb8a4b9faea9",
            "md5": "aba7f904d8cf31dd409cd51b2bd532bb",
            "request_id": "dxyOPeUGK3",
        }

        return [
            patch.object(
                IPQSFileScan,
                "_make_request",
                side_effect=[lookup_response, scan_response],
            ),
            patch.object(
                IPQSFileScan,
                "_poll_for_report",
                return_value=final_response,
            ),
        ]
