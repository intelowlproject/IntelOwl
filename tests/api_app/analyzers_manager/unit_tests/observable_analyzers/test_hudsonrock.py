from api_app.analyzers_manager.observable_analyzers.hudsonrock import HudsonRock
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse, patch


class HudsonRockTestCase(BaseAnalyzerTest):
    analyzer_class = HudsonRock

    @classmethod
    def get_extra_config(cls):
        return {
            "_api_key_name": "dummy-api-key",
            "observable_classification": "generic",  # to test login path
            "observable_name": "test@example.com",
            "page": 1,
            "sort_by": "asc",
            "installed_software": False,
        }

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.post",
            return_value=MockUpResponse(
                {
                    "credentials": [
                        {
                            "type": "client",
                            "domain": "disney.com",
                            "username": "••••",
                            "password": "••••",
                        }
                    ]
                },
                200,
            ),
        )
