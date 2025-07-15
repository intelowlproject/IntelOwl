from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.phunter import PhunterAnalyzer
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class PhunterAnalyzerTestCase(BaseAnalyzerTest):
    analyzer_class = PhunterAnalyzer

    @staticmethod
    def get_mocked_response():
        return patch(
            "api_app.analyzers_manager.observable_analyzers.phunter.requests.post",
            new=PhunterAnalyzer.mocked_docker_analyzer_post,
        )
