from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.hashlookup import HashLookupServer
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class HashLookupServerTestCase(BaseAnalyzerTest):
    analyzer_class = HashLookupServer

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "lookup": {
                "hash": "deadbeefdeadbeefdeadbeefdeadbeef",
                "found": True,
                "source": "hashlookup",
                "first_seen": "2022-01-01T00:00:00Z",
                "last_seen": "2023-01-01T00:00:00Z",
            }
        }
        return patch(
            "pyhashlookup.Hashlookup.lookup",
            return_value=mock_response,
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "hashlookup_server": "https://fake-hashlookup.local",
        }
