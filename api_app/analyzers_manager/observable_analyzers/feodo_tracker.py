# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import os
from typing import Tuple

import requests
from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class Feodo_Tracker(classes.ObservableAnalyzer):
    """
    Feodo Tracker offers various blocklists,
    helping network owners to protect their
    users from Dridex and Emotet/Heodo.
    """

    use_recommended_url: bool
    update_on_run: bool = True

    @classmethod
    @property
    def recommend_locations(cls) -> Tuple[str, str]:
        db_name = "feodotracker_abuse_ipblocklist.json"
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
        return f"{settings.MEDIA_ROOT}/{db_name}", url

    @classmethod
    @property
    def default_locations(cls) -> Tuple[str, str]:
        db_name = "feodotracker_abuse_ipblocklist_recommended.json"
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        return f"{settings.MEDIA_ROOT}/{db_name}", url

    def run(self):
        result = {"found": False}
        db_location, _ = (
            self.recommend_locations
            if self.use_recommended_url
            else self.default_locations
        )
        if self.update_on_run or not os.path.exists(db_location) and not self.update():
            raise AnalyzerRunException("Unable to update database")
        try:
            with open(db_location, "r", encoding="utf-8") as f:
                db = json.load(f)
            # db is a list of dictionaries
            for ip in db:
                if ip["ip_address"] == self.observable_name:
                    result["found"] = True
                    break
        except json.JSONDecodeError as e:
            raise AnalyzerRunException(f"Decode JSON in run: {e}")
        except FileNotFoundError as e:
            raise AnalyzerRunException(f"File not found in run: {e}")
        except KeyError as e:
            raise AnalyzerRunException(f"Key error in run: {e}")
        return result

    @classmethod
    def update(cls) -> bool:
        """
        Simply update the database
        """
        for db_location, db_url in [cls.default_locations, cls.recommend_locations]:
            logger.info(f"starting download of db from {db_url}")

            try:
                r = requests.get(db_url)
                r.raise_for_status()
            except requests.RequestException:
                return False
            with open(db_location, "w", encoding="utf-8") as f:
                try:
                    json.dump(r.json(), f)
                except json.JSONDecodeError:
                    return False
                logger.info(f"ended download of db from Feodo Tracker at {db_location}")
        return True

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        [
                            {
                                "ip_address": "196.218.123.202",
                                "port": 13783,
                                "status": "offline",
                                "hostname": "host-196.218.123.202-static.tedata.net",
                                "as_number": 8452,
                                "as_name": "TE-AS TE-AS",
                                "country": "EG",
                                "first_seen": "2023-10-23 17:04:20",
                                "last_online": "2024-02-06",
                                "malware": "Pikabot",
                            },
                            {
                                "ip_address": "51.161.81.190",
                                "port": 13721,
                                "status": "offline",
                                "hostname": None,
                                "as_number": 16276,
                                "as_name": "OVH",
                                "country": "CA",
                                "first_seen": "2023-12-18 18:29:21",
                                "last_online": "2024-01-23",
                                "malware": "Pikabot",
                            },
                            {
                                "ip_address": "185.117.90.142",
                                "port": 2222,
                                "status": "offline",
                                "hostname": None,
                                "as_number": 59711,
                                "as_name": "HZ-EU-AS",
                                "country": "NL",
                                "first_seen": "2024-01-17 18:58:25",
                                "last_online": "2024-01-22",
                                "malware": "QakBot",
                            },
                        ],
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
