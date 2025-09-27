from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.whoisripe import WhoIsRipeAPI
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class WhoIsRipeAPITestCase(BaseAnalyzerTest):
    analyzer_class = WhoIsRipeAPI

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "objects": {
                "object": [
                    {
                        "type": "inetnum",
                        "attributes": {
                            "attribute": [
                                {"name": "inetnum", "value": "192.0.2.0 - 192.0.2.255"},
                                {"name": "netname", "value": "EXAMPLE-NET"},
                            ]
                        },
                    }
                ]
            }
        }

        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {}
