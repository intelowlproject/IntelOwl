# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import os
from urllib.parse import urlparse

import requests
from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification

logger = logging.getLogger(__name__)

db_name = "phishing_army.txt"
database_location = f"{settings.MEDIA_ROOT}/{db_name}"


class PhishingArmy(classes.ObservableAnalyzer):
    url = "https://phishing.army/download/phishing_army_blocklist.txt"

    def run(self):
        result = {"found": False}
        if not os.path.isfile(database_location) and not self.update():
            raise AnalyzerRunException("Failed extraction of Phishing Army db")

        if not os.path.exists(database_location):
            raise AnalyzerRunException(f"database location {database_location} does not exist")

        with open(database_location, "r", encoding="utf-8") as f:
            db = f.read()

        db_list = db.split("\n")
        to_analyze_observable = self.observable_name
        if self.observable_classification == Classification.URL:
            to_analyze_observable = urlparse(self.observable_name).hostname

        if to_analyze_observable in db_list:
            result["found"] = True

        result["link"] = self.url

        return result

    @classmethod
    def update(cls):
        try:
            logger.info("starting download of db from Phishing Army")
            r = requests.get(cls.url)
            r.raise_for_status()

            with open(database_location, "w", encoding="utf-8") as f:
                f.write(r.content.decode())

            if not os.path.exists(database_location):
                return False

            logger.info("ended download of db from Phishing Army")
            return True
        except Exception as e:
            logger.exception(e)

        return False
