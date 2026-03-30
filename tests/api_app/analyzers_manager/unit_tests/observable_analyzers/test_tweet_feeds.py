from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.observable_analyzers.tweetfeeds import TweetFeeds
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class TweetFeedsTestCase(BaseAnalyzerTest):
    analyzer_class = TweetFeeds

    @staticmethod
    def get_mocked_response():
        mock_details = {
            "date": "2024-03-19 00:31:36",
            "user": "Metemcyber",
            "type": "url",
            "value": "http://210.56.49.214",
            "tags": ["#phishing"],
            "tweet": "https://twitter.com/Metemcyber/status/1769884392477077774",
        }
        return [
            patch(
                "api_app.analyzers_manager.observable_analyzers.tweetfeeds.TweetFeedItem.objects",
                **{
                    "exists.return_value": True,
                    "filter.return_value": MagicMock(
                        first=MagicMock(return_value=MagicMock(details=mock_details))
                    ),
                    "all.return_value": MagicMock(delete=MagicMock()),
                    "bulk_create.return_value": [],
                },
            ),
        ]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"filter1": "Metemcyber", "time": "month"}
