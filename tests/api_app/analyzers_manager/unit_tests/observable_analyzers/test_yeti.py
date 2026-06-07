# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

from requests.exceptions import HTTPError

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.yeti import YETI
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class MockResponse:
    # Mock replacement for requests.Response objects to support raise_for_status

    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise HTTPError(f"HTTP Error: {self.status_code}")


def mock_yeti_api_flow(url, *args, **kwargs):
    # Dynamic mock router to handle different YETI API endpoints

    if "api-token" in url:
        return MockResponse({"access_token": "mocked_jwt_token_123", "token_type": "bearer"}, 200)

    if "observables/search" in url:
        return MockResponse(
            {
                "total": 1,
                "observables": [
                    {
                        "id": "75297",
                        "type": "ipv4",
                        "value": "99.99.9.9",
                        "context": [{"source": "IntelOwl"}],
                    }
                ],
            },
            200,
        )

    return MockResponse({"detail": "Not Found"}, 404)


class YETITestCase(BaseAnalyzerTest):
    analyzer_class = YETI

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_url_key_name": "https://yeti.example.com",
            "_api_key_name": "test_yeti_api_key",
            "verify_ssl": False,
            "results_count": 10,
            "regex": False,
        }

    @staticmethod
    def get_mocked_response():
        return patch(
            "api_app.analyzers_manager.observable_analyzers.yeti.requests.post",
            side_effect=mock_yeti_api_flow,
        )

    def _setup_yeti_analyzer(self):
        """Helper to quickly spin up the analyzer for custom error tests."""
        return self._setup_analyzer(
            MagicMock(),
            "ipv4",
            "99.99.9.9",
        )

    def test_yeti_auth_failure_raises_exception(self):
        analyzer = self._setup_yeti_analyzer()

        with patch("api_app.analyzers_manager.observable_analyzers.yeti.requests.post") as mock_post:
            mock_post.return_value = MockResponse({"detail": "Unauthorized"}, 401)

            with self.assertRaisesRegex(AnalyzerRunException, "YETI Auth Request failed"):
                analyzer.run()

    def test_yeti_missing_access_token_raises_exception(self):
        analyzer = self._setup_yeti_analyzer()

        with patch("api_app.analyzers_manager.observable_analyzers.yeti.requests.post") as mock_post:
            mock_post.return_value = MockResponse({}, 200)

            with self.assertRaisesRegex(AnalyzerRunException, "Failed to obtain access token from YETI"):
                analyzer.run()
