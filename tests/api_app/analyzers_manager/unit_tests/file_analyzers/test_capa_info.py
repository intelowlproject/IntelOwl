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

    # overriding done to use real sample
    MIMETYPE_TO_FILENAME = BaseFileAnalyzerTest.MIMETYPE_TO_FILENAME.copy()
    MIMETYPE_TO_FILENAME["application/vnd.microsoft.portable-executable"] = (
        "d8f15132511e76a9fd806b12108f633c1d8f493527c6961c092e0499a9014048.exe"
    )

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
            "timeout": 120,
            "force_pull_signatures": False,
        }

    def test_capa_timeout_exception(self):
        from api_app.analyzers_manager.exceptions import AnalyzerRunException
        from api_app.analyzers_manager.models import AnalyzerConfig

        configs = AnalyzerConfig.objects.filter(python_module=self.analyzer_class.python_module)
        config = configs.first()
        analyzer = self.analyzer_class(config)
        analyzer.file_mimetype = "application/vnd.microsoft.portable-executable"
        analyzer.filename = "d8f15132511e76a9fd806b12108f633c1d8f493527c6961c092e0499a9014048.exe"
        analyzer.md5 = "mocked_md5_timeout"
        analyzer._FileAnalyzer__filepath = self.get_sample_file_path(analyzer.file_mimetype)

        for key, value in self.get_extra_config().items():
            setattr(analyzer, key, value)

        patches = self.get_mocked_response()

        with self._apply_patches(patches):
            with patch("api_app.analyzers_manager.file_analyzers.capa_info.subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(cmd=["capa"], timeout=120)
                with self.assertRaises(AnalyzerRunException) as context:
                    analyzer.run()

        self.assertIn("timed out after", str(context.exception))

    def test_reproducibility_sample_from_zip(self):
        """
        Test using a sample from the test_files setup to ensure reproducibility
        without external network dependencies.
        """
        from api_app.analyzers_manager.models import AnalyzerConfig

        mimetype = "application/vnd.microsoft.portable-executable"
        filepath = self.get_sample_file_path(mimetype)

        configs = AnalyzerConfig.objects.filter(python_module=self.analyzer_class.python_module)
        config = configs.first()
        analyzer = self.analyzer_class(config)
        analyzer.file_mimetype = mimetype
        analyzer.filename = self.MIMETYPE_TO_FILENAME[mimetype]
        analyzer.md5 = "mocked_md5_repro"
        analyzer._FileAnalyzer__filepath = filepath

        for key, value in self.get_extra_config().items():
            setattr(analyzer, key, value)

        patches = self.get_mocked_response()
        with self._apply_patches(patches):
            result = analyzer.run()
            self.assertIsNotNone(result)
            self.assertEqual(result["command_executed"][-1], f"{filepath}")


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
