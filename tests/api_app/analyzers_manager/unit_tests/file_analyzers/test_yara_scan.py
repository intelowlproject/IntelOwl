import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.yara_scan import YaraRepo, YaraScan

from .base_test_class import BaseFileAnalyzerTest


class TestYaraScan(BaseFileAnalyzerTest):
    analyzer_class = YaraScan

    def get_extra_config(self):
        return {
            "repositories": ["https://example.com/yara_rules.git"],
            "local_rules": "",
            "_private_repositories": {},
        }

    def get_mocked_response(self):
        return [
            patch(
                "api_app.analyzers_manager.file_analyzers.yara_scan.YaraRepo.analyze",
                return_value=[
                    {
                        "match": "test_rule",
                        "strings": [{"identifier": "$a", "plaintext": ["found"]}],
                        "tags": ["malware"],
                        "meta": {"author": "test"},
                        "path": "rules/test.yar",
                        "url": "https://example.com/yara_rules.git",
                        "rule_url": "https://example.com/yara_rules/blob/main/rules/test.yar",
                    }
                ],
            )
        ]

    def setUp(self):
        super().setUp()

        self.analyzer = YaraScan(
            {
                "repositories": [],
                "local_rules": "",
                "_private_repositories": {},
            }
        )

    @patch("api_app.analyzers_manager.file_analyzers.yara_scan.requests.get")
    def test_unprotect_update_downloads_yara_rules(self, mock_get):
        """
        Ensure Unprotect API repository downloads YARA rules with a non-empty
        yara_rule field and creates .yar files correctly.
        """

        # Mock API response
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "results": [
                {
                    "id": 1,
                    "name": "Test Rule",
                    "yara_rule": "rule test_rule { condition: true }",
                },
                {
                    "id": 2,
                    "name": "CAPA Rule",
                    "yara_rule": None,
                },
            ],
            "next": None,
        }

        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir)

            unprotect_repo = YaraRepo(url="https://unprotect.it/api/detection_rules/", directory=base_dir)

            # Call update on the correct repo
            unprotect_repo.update()

            # Verify HTTP request was made correctly
            mock_get.assert_called()
            called_url = mock_get.call_args[0][0]
            called_params = mock_get.call_args.kwargs.get("params", {})
            self.assertIn("unprotect.it/api/detection_rules/", called_url)
            self.assertEqual(called_params.get("page"), 1)

            # Verify .yar file was created
            created_files = list(base_dir.iterdir())
            self.assertEqual(len(created_files), 1)

            created_file = created_files[0]
            self.assertEqual(created_file.suffix, ".yar")
            self.assertEqual(created_file.name, "TestRule_1.yar")

            #  Verify file content
            with open(created_file, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertEqual(content, "rule test_rule { condition: true }")
