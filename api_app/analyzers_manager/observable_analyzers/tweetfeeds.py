import json
import logging
import os
from typing import Tuple

import requests
from django.conf import settings

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class TweetFeeds(ObservableAnalyzer):
    """
    wrapper for https://tweetfeed.live
    """

    url = "https://api.tweetfeed.live/v1/"
    filter1: str = ""
    update_on_run: bool = True
    time: str

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db_dir = os.path.join(settings.MEDIA_ROOT, "TweetFeedsDBs")
        self.create_db_dir()

    def create_db_dir(self):
        if not os.path.exists(self.db_dir):
            os.makedirs(self.db_dir)

    def location(self) -> Tuple[str, str]:
        if self.filter1 != "":
            url = (
                self.url
                + self.time
                + "/"
                + self.filter1
                + "/"
                + self.observable_classification
            )
        else:
            url = self.url + self.time + "/" + self.observable_classification

        db_name = f"""
        tweetfeed_{self.time}_{self.filter1}_{self.observable_classification}.json
        """

        return f"{settings.MEDIA_ROOT}/TweetFeedsDBs/{db_name}", url

    def run(self):
        db_location, url = self.location()
        logger.info(f"Running TweetFeeds {url} at {db_location}")
        if self.update_on_run or not os.path.exists(db_location):
            if not self.update():
                raise AnalyzerRunException("Unable to update database")

        with open(db_location, "r", encoding="utf-8") as f:
            try:
                db = json.load(f)
            except json.JSONDecodeError as e:
                raise AnalyzerRunException(f"Decode JSON in run: {e}")
            for tweet in db:
                if tweet["value"] == self.observable_name:
                    return tweet
        return {"found": False}

    def update(self) -> bool:
        db_location, db_url = self.location()
        logger.info(f"Updating TweetFeeds {db_url} at {db_location}")

        try:
            response = requests.get(db_url)
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"TweetFeeds failed to update {db_url}: {e}")
            return False
        with open(db_location, "w", encoding="utf-8") as f:
            try:
                json.dump(response.json(), f)
            except json.JSONDecodeError as e:
                logger.error(f"TweetFeeds failed to update {db_url}: {e}")
                return False
            logger.info(f"TweetFeeds updated {db_url}")
        return True

    @classmethod
    def _monkeypatch(cls):
        response = {
            {
                "date": "2024-03-19 00:31:36",
                "user": "Metemcyber",
                "type": "url",
                "value": "http://210.56.49.214",
                "tags": ["#phishing"],
                "tweet": "https://twitter.com/Metemcyber/status/1769884392477077774",
            },
            {
                "date": "2024-03-19 00:31:36",
                "user": "Metemcyber",
                "type": "url",
                "value": "https://www.bhafulp.cn",
                "tags": ["#phishing"],
                "tweet": "https://twitter.com/Metemcyber/status/1769884392477077774",
            },
        }
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        response,
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
