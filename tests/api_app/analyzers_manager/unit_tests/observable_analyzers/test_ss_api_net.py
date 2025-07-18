from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.ss_api_net import SSAPINet
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class SSAPINetTestCase(BaseAnalyzerTest):
    analyzer_class = SSAPINet

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.get",
            return_value=MockUpResponse({}, 200, content=b"hello world"),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "fake_ssapi_token",
            "use_proxy": False,
            "proxy": "",
            "output": "image",
            "extra_api_params": {"ttl": 300},
        }
