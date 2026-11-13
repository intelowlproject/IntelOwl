# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.virushee import VirusheeCheckHash
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class VirusheeCheckHashTestCase(BaseAnalyzerTest):
    analyzer_class = VirusheeCheckHash

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.Session.get",
            return_value=MockUpResponse(
                {
                    "success": True,
                    "file_info": {
                        "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                        "sha1": "deadbeefdeadbeefdeadbeefdeadbeef00000000",
                        "md5": "deadbeefdeadbeefdeadbeef00000000",
                        "file_type": "PE32",
                        "file_size": 204800,
                    },
                    "scan_results": {
                        "status": "found",
                        "positives": 42,
                        "total": 50,
                        "scan_date": "2024-01-01T00:00:00Z",
                        "engines": {
                            "ExampleAV": {
                                "detected": True,
                                "result": "Trojan.Generic",
                            }
                        },
                    },
                },
                200,
            ),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "dummy_api_key"}
