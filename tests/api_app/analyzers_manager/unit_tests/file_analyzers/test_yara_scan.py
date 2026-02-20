from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.yara_scan import YaraScan

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
