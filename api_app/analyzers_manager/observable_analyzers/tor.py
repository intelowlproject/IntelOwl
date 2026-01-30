# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import os
import re

import requests
from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)

db_name = "tor_exit_addresses.txt"
database_location = f"{settings.MEDIA_ROOT}/{db_name}"


class Tor(classes.ObservableAnalyzer):
    def _do_create_data_model(self) -> bool:
        return super()._do_create_data_model() and self.report.report["found"]

    def run(self):
        result = {"found": False}
        if not os.path.isfile(database_location) and not self.update():
            raise AnalyzerRunException("Failed extraction of tor db")

        if not os.path.exists(database_location):
            raise AnalyzerRunException(f"database location {database_location} does not exist")

        with open(database_location, "r", encoding="utf-8") as f:
            db = f.read()

        db_list = db.split("\n")
        if self.observable_name in db_list:
            result["found"] = True

        return result

    @classmethod
    def update(cls):
        try:
            logger.info("starting download of db from tor project")
            url = "https://check.torproject.org/exit-addresses"
            r = requests.get(url)
            r.raise_for_status()

            data_extracted = r.content.decode()
            findings = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", data_extracted)

            with open(database_location, "w", encoding="utf-8") as f:
                for ip in findings:
                    if ip:
                        f.write(f"{ip}\n")

            if not os.path.exists(database_location):
                return False

            logger.info("ended download of db from tor project")
            return True
        except Exception as e:
            logger.exception(e)

        return False
