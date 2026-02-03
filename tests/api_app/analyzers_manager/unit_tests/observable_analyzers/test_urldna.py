from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.urldna import UrlDNA
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class UrlDNATestCase(BaseAnalyzerTest):
    analyzer_class = UrlDNA

    @staticmethod
    def get_mocked_response():
        post_scan_response = {"id": "scan123"}
        get_result_response = {"scan": {"status": "DONE"}, "result": {"score": "clean"}}
        search_response = {"results": [{"domain": "example.com"}]}

        return [
            patch(
                "requests.Session.post",
                side_effect=[
                    MockUpResponse(search_response, 200),  # For SEARCH
                    MockUpResponse(post_scan_response, 200),  # For NEW_SCAN - scan request
                ],
            ),
            patch(
                "requests.Session.get",
                return_value=MockUpResponse(get_result_response, 200),
            ),
        ]

    @classmethod
    def get_extra_config(cls):
        return {
            "urldna_analysis": "SEARCH",  # change to "NEW_SCAN" if testing that mode
            "_api_key_name": "Bearer dummykey",
        }
