# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
from unittest.mock import AsyncMock, patch

from django.test import TestCase, override_settings

from api_app.chatbot.tools import execute_tool


def _mock_response(json_data, status_code=200):
    """Build a mock httpx.Response."""
    resp = AsyncMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.raise_for_status = AsyncMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
    return resp


@override_settings(CHATBOT_INTELOWL_BASE_URL="http://test:8001")
class TestExecuteTool(TestCase):
    """Test each tool function with mocked HTTP responses."""

    @patch("api_app.chatbot.tools.httpx.AsyncClient")
    async def test_search_jobs(self, mock_client_cls):
        client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        client.get.return_value = _mock_response(
            {"results": [{"id": 1}, {"id": 2}, {"id": 3}]}
        )

        result = await execute_tool(
            "search_jobs", {"observable_name": "evil.com", "limit": 2}, "test-token"
        )

        self.assertEqual(len(result["jobs"]), 2)
        client.get.assert_called_once()
        call_kwargs = client.get.call_args
        self.assertIn("Token test-token", call_kwargs.kwargs["headers"]["Authorization"])

    @patch("api_app.chatbot.tools.httpx.AsyncClient")
    async def test_get_job_report(self, mock_client_cls):
        client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        report_data = {
            "id": 42,
            "observable_name": "8.8.8.8",
            "analyzer_reports": [{"name": "AbuseIPDB", "status": "SUCCESS"}],
        }
        client.get.return_value = _mock_response(report_data)

        result = await execute_tool("get_job_report", {"job_id": 42}, "test-token")

        self.assertEqual(result["id"], 42)
        client.get.assert_called_once()

    @patch("api_app.chatbot.tools.httpx.AsyncClient")
    async def test_get_analyzer_config_found(self, mock_client_cls):
        client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        client.get.return_value = _mock_response(
            [{"name": "VirusTotal", "type": "observable"}, {"name": "Yara", "type": "file"}]
        )

        result = await execute_tool(
            "get_analyzer_config", {"analyzer_name": "VirusTotal"}, "test-token"
        )

        self.assertEqual(result["name"], "VirusTotal")

    @patch("api_app.chatbot.tools.httpx.AsyncClient")
    async def test_get_analyzer_config_not_found(self, mock_client_cls):
        client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        client.get.return_value = _mock_response([{"name": "Yara"}])

        result = await execute_tool(
            "get_analyzer_config", {"analyzer_name": "NonExistent"}, "test-token"
        )

        self.assertIn("error", result)

    @patch("api_app.chatbot.tools.httpx.AsyncClient")
    async def test_create_scan(self, mock_client_cls):
        client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        client.post.return_value = _mock_response(
            {"job_id": 99, "status": "accepted"}
        )

        result = await execute_tool(
            "create_scan",
            {
                "observable_name": "evil.com",
                "observable_classification": "domain",
                "analyzers_requested": [],
            },
            "test-token",
        )

        self.assertEqual(result["job_id"], 99)
        client.post.assert_called_once()
        payload = client.post.call_args.kwargs["json"]
        self.assertEqual(payload["observable_name"], "evil.com")

    async def test_unknown_tool(self):
        result = await execute_tool("nonexistent_tool", {}, "test-token")
        self.assertIn("error", result)
        self.assertIn("Unknown tool", result["error"])
