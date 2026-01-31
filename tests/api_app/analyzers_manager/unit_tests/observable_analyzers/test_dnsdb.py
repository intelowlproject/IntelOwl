from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.dnsdb import DNSdb
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class DNSdbTestCase(BaseAnalyzerTest):
    analyzer_class = DNSdb

    @staticmethod
    def get_mocked_response():
        mock_response = (
            '{"cond":"begin"}\n'
            '{"obj":{"count":1,"zone_time_first":1349367341,"zone_time_last":1440606099,'
            '"rrname":"mocked.data.net.","rrtype":"A","bailiwick":"net.","rdata":"0.0.0.0"}}\n'
            '{"cond":"limited","msg":"Result limit reached"}\n'
        )
        return patch(
            "requests.get",
            return_value=MockUpResponse(json_data={}, status_code=200, text=mock_response),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "test_dnsdb_key",
            "server": "mocked.dnsdb.io",
            "api_version": 2,
            "rrtype": "A",
            "query_type": "domain",
            "limit": 10,
            "time": {
                "first_after": "2020-01-01",
                "first_before": "",
                "last_after": "",
                "last_before": "",
            },
            "_time_first_after": "2020-01-01",
            "_time_first_before": "",
            "_time_last_after": "",
            "_time_last_before": "",
        }
