from unittest.mock import mock_open, patch

from api_app.analyzers_manager.observable_analyzers.cyberchef import CyberChef
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class CyberChefTestCase(BaseAnalyzerTest):
    analyzer_class = CyberChef

    @staticmethod
    def get_mocked_response():
        # Mock CyberChef server response
        mock_result = {
            "value": "ZXhhbXBsZS5jb20=",  # base64 encoded result
            "type": "string",
            "error": False,
            "duration": 0.125,
            "resultID": "abc123def456",
            "progress": 100,
        }

        # Mock recipe configuration file
        mock_recipes = {
            "base64_encode": [{"op": "To Base64", "args": ["A-Za-z0-9+/="]}],
            "decode_url": [
                {"op": "URL Decode", "args": []},
                {
                    "op": "Regular expression",
                    "args": [
                        "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
                        True,
                        True,
                        False,
                        False,
                        False,
                    ],
                },
            ],
        }

        return [
            patch("requests.post", return_value=MockUpResponse(mock_result, 200)),
            patch(
                "builtins.open",
                mock_open(read_data=str(mock_recipes).replace("'", '"')),
            ),
        ]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"recipe_name": "base64_encode", "output_type": "string"}
