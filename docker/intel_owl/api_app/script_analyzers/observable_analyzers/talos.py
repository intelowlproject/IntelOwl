import os
import logging
import traceback
import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import settings

logger = logging.getLogger(__name__)

db_name = "talos_ip_blacklist.txt"
database_location = f"{settings.MEDIA_ROOT}/{db_name}"


class Talos(classes.ObservableAnalyzer):
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

    @staticmethod
    def updater():
        try:
            logger.info("starting download of db from talos")
            url = "https://snort.org/downloads/ip-block-list"
            r = requests.get(url)
            r.raise_for_status()

            with open(database_location, "w") as f:
                f.write(r.content.decode())

            if not os.path.exists(database_location):
                raise AnalyzerRunException("failed extraction of talos db")

            logger.info("ended download of db from talos")

        except Exception as e:
            traceback.print_exc()
            logger.exception(e)

        return database_location
