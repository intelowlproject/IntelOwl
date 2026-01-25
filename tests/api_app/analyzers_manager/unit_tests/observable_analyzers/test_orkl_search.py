from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.orkl_search import OrklSearch
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class OrklSearchTestCase(BaseAnalyzerTest):
    analyzer_class = OrklSearch

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "data": [
                {
                    "id": "string",
                    "title": "string",
                    "sha1_hash": "deadbeefdeadbeefdeadbeefdeadbeef",
                    "threat_actors": [{"main_name": "SomeGroup"}],
                    "sources": [{"name": "Orkl", "url": "https://orkl.eu/some-entry"}],
                }
            ],
            "message": "Mocked Orkl response",
            "status": "ok",
        }

        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "full": False,
            "limit": 10,
        }
