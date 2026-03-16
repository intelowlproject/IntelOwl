from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.ipqsfile import IPQSFileScan

from .base_test_class import BaseFileAnalyzerTest


class TestIPQSFileScan(BaseFileAnalyzerTest):
    analyzer_class = IPQSFileScan

    def get_extra_config(self):
        return {
            "_ipqs_api_key": "dummy_key",
            "polling_interval": 0,
            "max_retries": 1,
        }

    def get_mocked_response(self):
        lookup_response = {
            "file_name": "test file.txt",
            "success": True,
            "message": "Success",
            "file_hash": "abc123",
            "type": "scan",
            "detected": False,
            "detected_scans": 0,
            "total_scans": 0,
            "status": "pending",
            "result": [""],
            "file_size": 10,
            "file_type": "text/plain",
            "request_id": "req1",
        }
        scan_response = {"success": True, "message": "Success", "request_id": "req1"}
        final_response = {**lookup_response, "status": "finished"}

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
