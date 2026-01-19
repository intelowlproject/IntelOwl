from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.malprob import MalprobScan
from tests.mock_utils import MockUpResponse

from .base_test_class import BaseFileAnalyzerTest


class TestMalprobScan(BaseFileAnalyzerTest):
    analyzer_class = MalprobScan

    def get_extra_config(self):
        return {"_api_key_name": "test_api_key_dummy"}

    def get_mocked_response(self):
        return patch(
            "requests.post",
            return_value=MockUpResponse(
                {
                    "report": {
                        "md5": "8a05a189e58ccd7275f7ffdf88c2c191",
                        "sha1": "a7a70f2f482e6b26eedcf1781b277718078c743a",
                        "sha256": "ac24043d48dadc390877a6151515565b1fdc1dab028ee2d95d80bd80085d9376",
                    },
                },
                200,
            ),
        )
