# tests/api_app/analyzers_manager/unit_tests/observable_analyzers/test_mb_google.py

from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.mb_google import MB_GOOGLE
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class MB_GOOGLETestCase(BaseAnalyzerTest):
    analyzer_class = MB_GOOGLE

    @staticmethod
    def get_mocked_response():
        return [
            patch(
                "api_app.analyzers_manager.observable_analyzers.mb_google.googlesearch.search",
                return_value=[
                    "https://bazaar.abuse.ch/sample/testhash1/",
                    "https://bazaar.abuse.ch/sample/testhash2/",
                ],
            ),
            patch(
                "api_app.analyzers_manager.observable_analyzers.mb_google.MB_GET.query_mb_api",
                side_effect=[
                    {"data": [{"sha256_hash": "testhash1"}]},
                    {"data": [{"sha256_hash": "testhash2"}]},
                ],
            ),
        ]
