# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import os
import re
import traceback

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from intel_owl import settings

logger = logging.getLogger(__name__)

db_name = "tor_exit_addresses.txt"
database_location = f"{settings.MEDIA_ROOT}/{db_name}"


class Tor(classes.ObservableAnalyzer):
    def run(self):
        result = {"found": False}
        if not os.path.isfile(database_location):
            self.updater()

        with open(database_location, "r") as f:
            db = f.read()

        db_list = db.split("\n")
        if self.observable_name in db_list:
            result["found"] = True

        return result

    @classmethod
    def updater(cls):
        if not cls.enabled:
            logger.warning("No running updater for Tor, because it is disabled")
            return
        try:
            logger.info("starting download of db from tor project")
            url = "https://check.torproject.org/exit-addresses"
            r = requests.get(url)
            r.raise_for_status()

            data_extracted = r.content.decode()
            findings = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", data_extracted)

            with open(database_location, "w") as f:
                for ip in findings:
                    if ip:
                        f.write(f"{ip}\n")

            if not os.path.exists(database_location):
                raise AnalyzerRunException("failed extraction of tor db")

            logger.info("ended download of db from tor project")

        except Exception as e:
            traceback.print_exc()
            logger.exception(e)

        return database_location
