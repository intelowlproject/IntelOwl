from unittest.mock import MagicMock, mock_open, patch

from api_app.analyzers_manager.file_analyzers.unpac_me import UnpacMe

from .base_test_class import BaseFileAnalyzerTest


class TestUnpacMe(BaseFileAnalyzerTest):
    analyzer_class = UnpacMe

    def get_extra_config(self):
        return {
            "_api_key_name": "test_api_key_12345",
            "private": True,
            "max_tries": 5,
            "headers": {},
            "poll_distance": 5,
        }

    def get_mocked_response(self):
        # Mock file reading
        mock_file_data = b"fake_binary_data_for_testing"

        # Mock POST response for upload
        mock_post_response = MagicMock()
        mock_post_response.json.return_value = {"id": "unpac_abc123def456"}
        mock_post_response.raise_for_status.return_value = None

        # Mock GET responses for status polling
        mock_status_response = MagicMock()
        mock_status_response.json.return_value = {"status": "complete"}
        mock_status_response.raise_for_status.return_value = None

        # Mock GET response for final report
        mock_report_response = MagicMock()
        mock_report_response.json.return_value = {
            "id": "unpac_abc123def456",
            "status": "complete",
            "sample": {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "filename": "malware.exe",
                "size": 4096,
                "mime_type": "application/x-executable",
            },
            "unpacked_sample": {
                "md5": "fedcba0987654321fedcba0987654321",
                "sha1": "1234567890abcdef1234567890abcdef12345678",
                "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "size": 8192,
                "download_url": "https://api.unpac.me/download/unpac_abc123def456",
            },
            "metadata": {
                "submitted_at": "2024-01-15T10:30:00Z",
                "analyzed_at": "2024-01-15T10:32:15Z",
                "processing_time": 135,
            },
        }
        mock_report_response.raise_for_status.return_value = None

        return [
            patch("builtins.open", mock_open(read_data=mock_file_data)),
            patch(
                "api_app.analyzers_manager.file_analyzers.unpac_me.requests.post",
                return_value=mock_post_response,
            ),
            patch(
                "api_app.analyzers_manager.file_analyzers.unpac_me.requests.get",
                side_effect=[mock_status_response, mock_report_response],
            ),
            patch("api_app.analyzers_manager.file_analyzers.unpac_me.time.sleep"),
        ]
