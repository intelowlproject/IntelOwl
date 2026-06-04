# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

from requests.exceptions import HTTPError

from api_app.connectors_manager.connectors.yeti import YETI
from api_app.connectors_manager.exceptions import ConnectorRunException
from tests.api_app.connectors_manager.unit_tests.base_test_class import BaseConnectorTest


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

    if "observables/extended" in url:
        return MockResponse(
            {
                "context": [
                    {
                        "source": "IntelOwl",
                        "report": "https://intelowl.example/jobs/51",
                        "status": "analyzed",
                        "date": "2026-06-02T12:34:56Z",
                        "description": "IntelOwl analysis report for Job: 51 | 1.2.3.4 | ipv4",
                        "analyzers executed": "IPApi",
                    }
                ],
                "tags": [
                    {
                        "name": "intelowl",
                        "last_seen": "2026-06-04T08:45:45.136845Z",
                        "expires": "2026-09-02T08:45:45.136845Z",
                        "fresh": True,
                        "id": None,
                    }
                ],
                "value": "1.2.3.4",
                "last_analysis": {},
                "created": "2026-06-04T08:45:45.086020Z",
                "modified": "2026-06-04T08:45:45.186824Z",
                "type": "ipv4",
                "id": "12345",
                "acls": {},
                "root_type": "observable",
                "is_valid": True,
            },
            200,
        )

    return MockResponse({"detail": "Not Found"}, 404)


class YETITestCase(BaseConnectorTest):
    connector_class = YETI

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_url_key_name": "http://yeti.local/",
            "_api_key_name": "dummy_api_key",
            "verify_ssl": False,
            "job_id": 51,
        }

    @staticmethod
    def get_mocked_response():
        return [
            patch("api_app.connectors_manager.connectors.yeti.requests.post", side_effect=mock_yeti_api_flow)
        ]

    def _create_mock_job(self, observable_name, observable_type):
        mock_job = super()._create_mock_job(observable_name, observable_type)

        mock_tags = MagicMock()
        mock_tags.all().values_list.return_value = ["intelowl"]
        mock_job.tags = mock_tags

        mock_analyzers = MagicMock()
        mock_analyzers.all().values_list.return_value = ["IPApi"]
        mock_job.analyzers_to_execute = mock_analyzers

        mock_job.received_request_time = "2026-06-04 08:36:35.035498+00:00"

        return mock_job

    def test_yeti_run_with_file_sample(self):
        connector = self._setup_connector()

        mock_job = self._create_mock_job("xyz_filename", "file")
        mock_job.is_sample = True
        mock_job.analyzable.md5 = "abcdef1234567890abcdef1234567890"
        connector._job = mock_job

        # enforce the mock during this specific execution
        with patch(
            "api_app.connectors_manager.connectors.yeti.requests.post", side_effect=mock_yeti_api_flow
        ):
            result = connector.run()

        self.assertEqual(result.get("id"), "12345")
        self.assertEqual(result.get("type"), "ipv4")
        self.assertTrue(result.get("is_valid"))
        self.assertEqual(len(result.get("context", [])), 1)

    def test_yeti_auth_failure_raises_exception(self):
        connector = self._setup_connector()

        with patch("api_app.connectors_manager.connectors.yeti.requests.post") as mock_post:
            mock_post.return_value = MockResponse({"error": "Unauthorized"}, 401)

            with self.assertRaisesRegex(ConnectorRunException, "YETI Auth Request failed"):
                connector.run()

    def test_yeti_missing_access_token_raises_exception(self):
        connector = self._setup_connector()

        with patch("api_app.connectors_manager.connectors.yeti.requests.post") as mock_post:
            mock_post.return_value = MockResponse({}, 200)

            with self.assertRaisesRegex(ConnectorRunException, "Failed to obtain access token from YETI"):
                connector.run()
