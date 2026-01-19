# tests/api_app/analyzers_manager/unit_tests/observable_analyzers/test_mb_get.py

from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.mb_get import MB_GET
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class MB_GETTestCase(BaseAnalyzerTest):
    analyzer_class = MB_GET

    @staticmethod
    def get_mocked_response():
        return patch.object(
            MB_GET,
            "run",
            return_value={
                "data": [{"sha256_hash": "test"}],
            },
        )
