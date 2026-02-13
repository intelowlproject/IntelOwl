from unittest.mock import patch

import requests
from django.conf import settings

from api_app.analyzers_manager.file_analyzers.virushee import VirusheeFileUpload

from .base_test_class import BaseFileAnalyzerTest


class TestVirusheeFileUpload(BaseFileAnalyzerTest):
    analyzer_class = VirusheeFileUpload

    def get_extra_config(self):
        return {
            "_api_key_name": "fake_api_key",
            "force_scan": False,
            "_VirusheeFileUpload__session": requests.Session(),
        }

    def get_mocked_response(self):
        patches = [
            patch(
                "requests.Session.get",
                side_effect=[
                    # __check_report_for_hash
                    self.MockUpResponse({"message": "hash_not_found"}, 404),
                    # __poll_status_and_result - analysis in progress
                    self.MockUpResponse({"message": "analysis_in_progress"}, 202),
                    # __poll_status_and_result - final result
                    self.MockUpResponse({"result": "test"}, 200),
                ],
            ),
            patch(
                "requests.Session.post",
                return_value=self.MockUpResponse({"task": "123-456-789"}, 201),
            ),
        ]

        if settings.MOCK_CONNECTIONS:
            patches.append(patch("time.sleep", return_value=None))
        return patches

    class MockUpResponse:
        """Simple mock response class to simulate requests.Response"""

        def __init__(self, json_data, status_code):
            self._json = json_data
            self.status_code = status_code

        def json(self):
            return self._json

        def raise_for_status(self):
            if self.status_code >= 400:
                raise Exception(f"HTTP Error {self.status_code}")
