import json
import logging
import os
from typing import Tuple

import requests
from django.conf import settings

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class TweetFeeds(ObservableAnalyzer):
    """
    Wrapper for https://tweetfeed.live api
    """

    url = "https://api.tweetfeed.live/v1/"
    filter1: str = ""
    time: str = ""

    @classmethod
    def location(cls) -> Tuple[str, str]:
        db_name = "tweetfeed_month.json"
        url = "https://api.tweetfeed.live/v1/month"
        return f"{settings.MEDIA_ROOT}/{db_name}", url

    def run_url(self) -> str:
        if self.filter1:
            url = self.url + self.time + "/" + self.filter1 + "/" + self.observable_classification
        else:
            url = self.url + self.time + "/" + self.observable_classification
        return url

    def run(self):
        # update logic for first time run
        default_db, default_url = self.location()
        if not os.path.exists(default_db) and not self.update():
            raise AnalyzerRunException(f"Could not find or update db at {default_db} using {default_url}")

        with open(default_db, "r", encoding="utf-8") as f:
            logger.info(f"TweetFeeds running with {default_db}")
            db = json.load(f)
            for tweet in db:
                if tweet["value"] == self.observable_name:
                    if self.filter1 and (self.filter1 in tweet["tags"] or self.filter1 == tweet["user"]):
                        # this checks if our user has demanded for a
                        # specific filter and return data based on the
                        # filter in default db
                        return tweet
                    elif not self.filter1:
                        return tweet

        if self.time == "year":
            # we already have the updated data for the month
            # (covers week and today options) with us;
            # year is the only extended version possible
            run_url = self.run_url()
            logger.info(f"TweetFeeds extending using {run_url}")

            # simply make api call and search for observable
            response = requests.get(run_url)
            response.raise_for_status()
            db = response.json()
            for tweet in db:
                if tweet["value"] == self.observable_name:
                    return tweet

        return {"found": False}

    @classmethod
    def update(cls) -> bool:
        """
        Update TweetFeeds database:
        Our default DB gets data with
        no filter for the past month
        """

        db_location, db_url = cls.location()
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
