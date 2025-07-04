from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.dehashed import DehashedSearch
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class DehashedSearchTestCase(BaseAnalyzerTest):
    analyzer_class = DehashedSearch

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "entries": [
                {
                    "id": "test123",
                    "email": "test@example.com",
                    "username": "testuser",
                    "password": "testpass",
                }
            ]
        }

        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "size": 100,
            "pages": 1,
            "operator": "password",  # Set default operator for hash types
            "_api_key_name": "test_api_key:test_password",
        }
