# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""
Talos IP blocklist analyzer (Cisco/Snort).

Note: As of 2024, the blocklist at snort.org requires accepting terms and conditions
in a browser. If automatic download fails (e.g. HTML T&C page returned), download
the list manually from https://snort.org/downloads/ip-block-list and place it at
MEDIA_ROOT/talos_ip_blacklist.txt.
"""

import logging
import os

import requests
from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)

db_name = "talos_ip_blacklist.txt"
database_location = f"{settings.MEDIA_ROOT}/{db_name}"


class Talos(classes.ObservableAnalyzer):
    def run(self):
        result = {"found": False}
        if not os.path.isfile(database_location) and not self.update():
            raise AnalyzerRunException("Failed extraction of talos db")

        if not os.path.exists(database_location):
            raise AnalyzerRunException(f"database location {database_location} does not exist")

        with open(database_location, "r", encoding="utf-8") as f:
            db = f.read()

        db_list = db.split("\n")
        if self.observable_name in db_list:
            result["found"] = True

        return result

    @classmethod
    def update(cls) -> bool:
        try:
            logger.info("starting download of db from talos")
            url = "https://snort.org/downloads/ip-block-list"
            r = requests.get(url, timeout=60)
            r.raise_for_status()

            content_type = (r.headers.get("Content-Type") or "").lower()
            if "text/html" in content_type:
                logger.warning(
                    "Talos blocklist URL returned HTML (likely T&C page). "
                    "Download the list manually from %s and place it at %s",
                    url,
                    database_location,
                )
                return False

            with open(database_location, "w", encoding="utf-8") as f:
                f.write(r.content.decode())

            if not os.path.exists(database_location):
                return False
            logger.info("ended download of db from talos")
            return True
        except Exception as e:
            logger.exception(e)

        return False

    def _do_create_data_model(self):
        return super()._do_create_data_model()

    def _update_data_model(self, data_model):
        super()._update_data_model(data_model)
        found = self.report.report.get("found", False)
        if found:
            data_model.external_references.append(
                f"https://www.talosintelligence.com/reputation_center/lookup?search={self.report.job.analyzable.name}"
            )
            data_model.evaluation = self.EVALUATIONS.MALICIOUS.value
