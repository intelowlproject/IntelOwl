from api_app.analyzers_manager.observable_analyzers.haveibeenpwned import HaveIBeenPwned
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse, patch


class HaveIBeenPwnedTestCase(BaseAnalyzerTest):
    analyzer_class = HaveIBeenPwned

    @classmethod
    def get_extra_config(cls):
        return {
            "truncate_response": True,
            "include_unverified": False,
            "domain": "",
            "_api_key_name": "dummy-key",
        }

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.get",
            return_value=MockUpResponse({}, 200),
        )
