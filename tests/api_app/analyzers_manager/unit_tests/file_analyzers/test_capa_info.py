import subprocess
from unittest import TestCase
from unittest.mock import MagicMock, patch

from django.conf import settings

from api_app.analyzers_manager.file_analyzers.capa_info import (
    CACHE_LOCATION,
    CapaInfo,
)

from .base_test_class import BaseFileAnalyzerTest


class TestCapaInfoAnalyzer(BaseFileAnalyzerTest):
    analyzer_class = CapaInfo

    def get_mocked_response(self):
        response_from_command = subprocess.CompletedProcess(
            args=[
                "capa",
                "--quiet",
                "--json",
                "-r",
                "/opt/deploy/files_required/capa/capa-rules",
                "-s",
                "/opt/deploy/files_required/capa/sigs",
                "/opt/deploy/files_required/06ebf06587b38784e2af42dd5fbe56e5",
            ],
            returncode=0,
            stdout='{"meta": {}, "rules": {"contain obfuscated stackstrings": {}, "enumerate PE sections":{}}}',
            stderr="",
        )

        mock_requests_get = MagicMock()
        mock_requests_get.json.return_value = {"tag_name": "v1.0.0"}

        patches = [
            patch.object(CapaInfo, "update", return_value=True),
            patch("subprocess.run", return_value=response_from_command),
            patch(
                "api_app.analyzers_manager.file_analyzers.capa_info.requests.get",
                return_value=mock_requests_get,
            ),
            patch.object(CapaInfo, "_check_if_latest_version", return_value=True),
        ]

        if settings.MOCK_CONNECTIONS:
            patches.insert(1, patch.object(CapaInfo, "_download_signatures", return_value=None))
        return patches

    def get_extra_config(self):
        return {
            "shellcode": False,
            "arch": "64",
            "timeout": 15,
            "force_pull_signatures": False,
        }


class TestCapaInfoCacheDirectory(TestCase):
    @patch(
        "api_app.analyzers_manager.file_analyzers.capa_info.os.access",
        return_value=True,
    )
    @patch("api_app.analyzers_manager.file_analyzers.capa_info.os.makedirs")
    @patch(
        "api_app.analyzers_manager.file_analyzers.capa_info.os.path.isdir",
        return_value=False,
    )
    def test_ensure_cache_creates_directory(self, mock_isdir, mock_makedirs, mock_access):
        result = CapaInfo._ensure_cache_directory()
        mock_makedirs.assert_called_once_with(CACHE_LOCATION, mode=0o755, exist_ok=True)
        self.assertEqual(result, CACHE_LOCATION)

    @patch(
        "api_app.analyzers_manager.file_analyzers.capa_info.os.access",
        return_value=True,
    )
    @patch(
        "api_app.analyzers_manager.file_analyzers.capa_info.os.path.isdir",
        return_value=True,
    )
    def test_ensure_cache_writable_returns_path(self, mock_isdir, mock_access):
        result = CapaInfo._ensure_cache_directory()
        self.assertEqual(result, CACHE_LOCATION)

    @patch(
        "api_app.analyzers_manager.file_analyzers.capa_info.os.access",
        side_effect=[False, True],
    )
    @patch("api_app.analyzers_manager.file_analyzers.capa_info.os.chmod")
    @patch(
        "api_app.analyzers_manager.file_analyzers.capa_info.os.path.isdir",
        return_value=True,
    )
    def test_ensure_cache_fixes_permissions(self, mock_isdir, mock_chmod, mock_access):
        result = CapaInfo._ensure_cache_directory()
        mock_chmod.assert_called_once_with(CACHE_LOCATION, 0o700)
        self.assertEqual(result, CACHE_LOCATION)

    @patch(
        "api_app.analyzers_manager.file_analyzers.capa_info.tempfile.mkdtemp",
        return_value="/tmp/capa_cache_xyz",
    )
    @patch(
        "api_app.analyzers_manager.file_analyzers.capa_info.os.chmod",
        side_effect=OSError("Permission denied"),
    )
    @patch(
        "api_app.analyzers_manager.file_analyzers.capa_info.os.access",
        return_value=False,
    )
    @patch(
        "api_app.analyzers_manager.file_analyzers.capa_info.os.path.isdir",
        return_value=True,
    )
    def test_ensure_cache_falls_back_to_tempdir(self, mock_isdir, mock_access, mock_chmod, mock_mkdtemp):
        result = CapaInfo._ensure_cache_directory()
        mock_mkdtemp.assert_called_once_with(prefix="capa_cache_")
        self.assertEqual(result, "/tmp/capa_cache_xyz")

    @patch(
        "api_app.analyzers_manager.file_analyzers.capa_info.tempfile.mkdtemp",
        return_value="/tmp/capa_cache_abc",
    )
    @patch(
        "api_app.analyzers_manager.file_analyzers.capa_info.os.makedirs",
        side_effect=OSError("Permission denied"),
    )
    @patch(
        "api_app.analyzers_manager.file_analyzers.capa_info.os.path.isdir",
        return_value=False,
    )
    def test_ensure_cache_falls_back_on_creation_failure(self, mock_isdir, mock_makedirs, mock_mkdtemp):
        result = CapaInfo._ensure_cache_directory()
        mock_mkdtemp.assert_called_once_with(prefix="capa_cache_")
        self.assertEqual(result, "/tmp/capa_cache_abc")
