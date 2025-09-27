from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.file_info import FileInfo

from .base_test_class import BaseFileAnalyzerTest


class TestFileInfo(BaseFileAnalyzerTest):
    analyzer_class = FileInfo

    def get_mocked_response(self):
        return [
            # Mock file type detection
            patch(
                "magic.from_file",
                side_effect=lambda path, mime=False: (
                    "application/pdf" if mime else "PDF document, version 1.4"
                ),
            ),
            # Mock hash functions
            patch(
                "api_app.helpers.calculate_md5",
                return_value="d41d8cd98f00b204e9800998ecf8427e",
            ),
            patch(
                "api_app.helpers.calculate_sha1",
                return_value="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            ),
            patch(
                "api_app.helpers.calculate_sha256",
                return_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            patch("pydeep.hash_file", return_value=b"3:AOn4:An"),
            patch("tlsh.hash", return_value="T1234567890ABCDEF"),
            # Disable exiftool to avoid subprocess issues
            patch.object(FileInfo, "exiftool_path", None),
        ]
