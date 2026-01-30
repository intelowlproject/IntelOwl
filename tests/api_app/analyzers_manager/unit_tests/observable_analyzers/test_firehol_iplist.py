from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.firehol_iplist import FireHol_IPList
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class FireHolIPListTestCase(BaseAnalyzerTest):
    analyzer_class = FireHol_IPList

    @classmethod
    def get_extra_config(cls):
        return {"list_names": ["example.ipset"]}

    @staticmethod
    def get_mocked_response():
        # Simulates downloading an IP list with the target IP inside
        text_data = "# comment line\n0.0.0.0/8\n3.90.198.217\n5.0.0.0/8\n"
        return patch(
            "requests.get",
            return_value=MockUpResponse(
                json_data={},
                status_code=200,
                text=text_data,
            ),
        )
