from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.ipapi import IPApi
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class IPApiTestCase(BaseAnalyzerTest):
    analyzer_class = IPApi

    @staticmethod
    def get_mocked_response():
        mock_ip_info = [{"query": "8.8.8.8", "country": "United States", "status": "success"}]
        mock_dns_info = {"dns": "mock_dns_data"}

        return [
            patch("requests.post", return_value=MockUpResponse(mock_ip_info, 200)),
            patch("requests.get", return_value=MockUpResponse(mock_dns_info, 200)),
        ]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"fields": "query,country,status", "lang": "en", "IP": ""}
