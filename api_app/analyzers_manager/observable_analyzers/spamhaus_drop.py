import bisect
import ipaddress
import json
import logging
import os

import requests
from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class SpamhausDropV4(classes.ObservableAnalyzer):

    url = "https://www.spamhaus.org/drop/drop_v4.json"
    ipv6_url = "https://www.spamhaus.org/drop/drop_v6.json"

    @classmethod
    def location(cls, type: str) -> str:
        if type == "ipv4":
            db_name = "drop_v4_2.json"
        else:
            db_name = "drop_v6_2.json"
        return f"{settings.MEDIA_ROOT}/{db_name}"

    def run(self):
        ip = ipaddress.ip_address(self.observable_name)
        if ip.version == 4:
            print("The given observable is an IPv4 address.")
            type = "ipv4"

        elif ip.version == 6:
            print("The given observable is an IPv6 address.")
            type = "ipv6"

        database_location = self.location(type)

        if not os.path.exists(database_location):
            print(f"Database does not exist in {database_location}, initialising...")
            self.update(type)
        with open(database_location, "r") as f:
            db = json.load(f)

        insertion = bisect.bisect_left(
            db, ip, key=lambda x: ipaddress.ip_network(x["cidr"]).network_address
        )
        matches = []
        # Check entries at and after the insertion point
        # there maybe one or more subnets contained in the ip
        for i in range(insertion, len(db)):
            network = ipaddress.ip_network(db[i]["cidr"])
            if ip in network:
                matches.append(db[i])
            elif network.network_address > ip:
                break
        if matches:
            return {"found": True, "details": matches}

        return {"found": False}

    @classmethod
    def update(cls, type: str):
        if type == "ipv4":
            logger.info(f"Updating database from {cls.url}")
            db_url = cls.url
        else:
            logger.info(f"Updating database from {cls.ipv6_url}")
            db_url = cls.ipv6_url
        response = requests.get(url=db_url)
        response.raise_for_status()
        data = cls.convert_to_json(response.text)
        print("data", data)
        database_location = cls.location(type)
        with open(database_location, "w", encoding="utf-8") as f:
            json.dump(data, f)
        print(f"Database updated at {database_location}")

    @staticmethod
    def convert_to_json(input_string) -> dict:
        lines = input_string.strip().split("\n")
        json_objects = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                json_obj = json.loads(line)
                json_objects.append(json_obj)
            except json.JSONDecodeError:
                raise AnalyzerRunException(
                    "Invalid JSON format in the response while updating the database"
                )

        return json_objects

    @classmethod
    def _monkeypatch(cls):
        mock_data = (
            '{"cidr": "1.10.16.0/20", "sblid": "SBL256894", "rir": "apnic"}\n'
            '{"cidr": "2.56.192.0/22", "sblid": "SBL459831", "rir": "ripencc"}'
        )
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        mock_data,
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
