from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.malprob import MalprobSearch
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class MalprobSearchTestCase(BaseAnalyzerTest):
    analyzer_class = MalprobSearch

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "report": {
                "name": "sample.apk",
                "label": "benign",
                "mime": "application/java-archive",
                "score": 0.0003,
                "sha256": "ac24043d48dadc390877a6151515565b1fdc1dab028ee2d95d80bd80085d9376",
                "nested": [
                    {
                        "name": "classes.dex",
                        "type": "application/octet-stream",
                        "complete": True,
                    }
                ],
                "supported": True,
            }
        }

        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))
