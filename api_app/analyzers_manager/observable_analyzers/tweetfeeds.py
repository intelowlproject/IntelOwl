import logging

import requests
from django.db import transaction

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.models import TweetFeedItem

logger = logging.getLogger(__name__)


class TweetFeeds(ObservableAnalyzer):
    """
    Wrapper for https://tweetfeed.live api
    """

    url = "https://api.tweetfeed.live/v1/"
    filter1: str = ""
    time: str = ""

    db_url: str = "https://api.tweetfeed.live/v1/month"

    def run_url(self) -> str:
        if self.filter1:
            url = self.url + self.time + "/" + self.filter1 + "/" + self.observable_classification
        else:
            url = self.url + self.time + "/" + self.observable_classification
        return url

    def run(self):
        if not TweetFeedItem.objects.exists():
            logger.info("TweetFeedItem table is empty, triggering update...")
            self.update()

        qs = TweetFeedItem.objects.filter(value=self.observable_name)
        if self.filter1:
            # filter by tag or user stored in details
            for item in qs:
                details = item.details
                tags = details.get("tags", []) or []
                user = details.get("user", "")
                if self.filter1 in tags or self.filter1 == user:
                    return details
        else:
            item = qs.first()
            if item:
                return item.details

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
        logger.info(f"Updating TweetFeeds from {cls.db_url}")

        try:
            response = requests.get(cls.db_url)
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"TweetFeeds failed to update: {e}")
            return False

        try:
            data = response.json()
        except Exception as e:
            logger.error(f"TweetFeeds failed to parse response: {e}")
            return False

        with transaction.atomic():
            TweetFeedItem.objects.all().delete()
            TweetFeedItem.objects.bulk_create(
                [TweetFeedItem(value=item["value"], details=item) for item in data if item.get("value")],
                batch_size=1000,
                ignore_conflicts=True,
            )

        logger.info(f"Updated {len(data)} TweetFeedItem entries")
        return True
