from api_app.analyzers_manager.observable_analyzers.honeydb import HoneyDB
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse, patch


class HoneyDBTestCase(BaseAnalyzerTest):
    analyzer_class = HoneyDB

    @classmethod
    def get_extra_config(cls):
        return {
            "_api_key_name": "dummy-key",
            "_api_id_name": "dummy-id",
            "honeydb_analysis": "ip_query",
            "headers": {
                "X-HoneyDb-ApiKey": "dummy-key",
                "X-HoneyDb-ApiId": "dummy-id",
            },
            "result": {},
            "endpoints": [
                "scan_twitter",
                "ip_query",
                "ip_history",
                "internet_scanner",
                "ip_info",
            ],
        }

    @staticmethod
    def get_mocked_response():
        return patch("requests.get", return_value=MockUpResponse({}, 200))
