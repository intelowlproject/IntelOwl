import json
from unittest.mock import mock_open, patch

from api_app.analyzers_manager.observable_analyzers.tweetfeeds import TweetFeeds
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class TweetFeedsTestCase(BaseAnalyzerTest):
    analyzer_class = TweetFeeds

    @staticmethod
    def get_mocked_response():
        mock_data = [
            {
                "date": "2024-03-19 00:31:36",
                "user": "Metemcyber",
                "type": "url",
                "value": "http://210.56.49.214",
                "tags": ["#phishing"],
                "tweet": "https://twitter.com/Metemcyber/status/1769884392477077774",
            }
        ]

        return [
            patch("builtins.open", mock_open(read_data=json.dumps(mock_data))),
            patch("os.path.exists", return_value=True),
            patch("requests.get", return_value=MockUpResponse(mock_data, 200)),
        ]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"filter1": "Metemcyber", "time": "month"}
