# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import os

import requests
from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)

db_name = "talos_ip_blacklist.txt"
database_location = f"{settings.MEDIA_ROOT}/{db_name}"


class Talos(classes.ObservableAnalyzer):
    def run(self):
        result = {"found": False}
        if not os.path.isfile(database_location):
            if not self.update():
                raise AnalyzerRunException("Failed extraction of talos db")

        if not os.path.exists(database_location):
            raise AnalyzerRunException(
                f"database location {database_location} does not exist"
            )

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
            r = requests.get(url)
            r.raise_for_status()

            with open(database_location, "w", encoding="utf-8") as f:
                f.write(r.content.decode())

            if not os.path.exists(database_location):
                return False
            logger.info("ended download of db from talos")
            return True
        except Exception as e:
            logger.exception(e)

        return False

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({}, 200, content=b"91.192.100.61"),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
