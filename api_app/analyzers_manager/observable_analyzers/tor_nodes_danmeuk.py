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

db_name = "tor_nodes_addresses.txt"
database_location = f"{settings.MEDIA_ROOT}/{db_name}"


class TorNodesDanMeUK(classes.ObservableAnalyzer):
    def run(self):
        result = {"found": False}
        if not os.path.isfile(database_location) and not self.update():
            raise AnalyzerRunException("Failed extraction of tor db")

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
    def update(cls):
        try:
            logger.info("starting download of tor nodes from https://dan.me.uk")
            url = "https://www.dan.me.uk/torlist/?full"
            r = requests.get(url)
            r.raise_for_status()

            data_extracted = r.content.decode()
            tor_nodes_list = data_extracted.split("\n")

            with open(database_location, "w", encoding="utf-8") as f:
                for ip in tor_nodes_list:
                    if ip:
                        f.write(f"{ip}\n")

            if not os.path.exists(database_location):
                return False

            logger.info("ended download of tor nodes from https://dan.me.uk")
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
                    return_value=MockUpResponse(
                        {},
                        200,
                        content=b"""100.10.37.131
100.14.156.183
100.16.153.149
100.4.55.171
100.8.8.137
101.100.141.137
101.55.125.10
102.119.243.196""",
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
