from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.yaraify_file_scan import YARAifyFileScan

from .base_test_class import BaseFileAnalyzerTest


class TestYARAifyFileScan(BaseFileAnalyzerTest):
    analyzer_class = YARAifyFileScan

    def get_extra_config(self):
        return {
            "_api_key_identifier": "test_key",
            "clamav_scan": True,
            "unpack": False,
            "share_file": True,
            "skip_noisy": False,
            "skip_known": True,
            "send_file": True,
            "max_tries": 2,
        }

    def get_mocked_response(self):
        # Patch both YARAify.run() and requests.post()
        return [
            patch(
                "api_app.analyzers_manager.observable_analyzers.yaraify.YARAify.run",
                return_value={"query_status": "not_found"},
            ),
            patch("requests.post", side_effect=self.mock_requests_post),
        ]

    @staticmethod
    def mock_requests_post(url, files=None, json=None, headers=None, **kwargs):
        # Simulate initial file upload response (returns task_id)
        if files:
            return MagicMock(
                status_code=200,
                json=lambda: {
                    "query_status": "queued",
                    "data": {"task_id": "dummy-task-id"},
                },
            )

        # Simulate polling request
        elif json and json.get("query") == "get_results":
            return MagicMock(
                status_code=200,
                json=lambda: {
                    "query_status": "ok",
                    "data": {
                        "scan_result": "suspicious",
                        "matched_rules": ["malicious_rule_1"],
                    },
                },
            )

        # Default fallback
        return MagicMock(status_code=400, json=lambda: {"error": "bad request"})
