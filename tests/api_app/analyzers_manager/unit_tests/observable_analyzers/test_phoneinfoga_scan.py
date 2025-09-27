from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.phoneinfoga_scan import Phoneinfoga
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class PhoneinfogaTestCase(BaseAnalyzerTest):
    analyzer_class = Phoneinfoga

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_NUMVERIFY_API_KEY": "mock-numverify-key",
            "_GOOGLECSE_CX": "mock-cx",
            "_GOOGLE_API_KEY": "mock-google-key",
            "all_scanners": True,
        }

    @staticmethod
    def get_mocked_response():
        return patch("requests.post", new=Phoneinfoga.mocked_docker_analyzer_post)
