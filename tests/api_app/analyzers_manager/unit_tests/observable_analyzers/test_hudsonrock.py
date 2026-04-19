from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
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

    def test_invalid_generic_raises_exception(self):
        config = self.get_extra_config()
        config["observable_name"] = "johndoe123"

        analyzer = self.analyzer_class(**config)
        with self.assertRaises(AnalyzerConfigurationException):
            analyzer.run()
