import bisect
import ipaddress
import json
import logging
import os

import requests
from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class SpamhausDropV4(classes.ObservableAnalyzer):
    url = "https://www.spamhaus.org/drop"
    ipv4_url = url + "/drop_v4.json"
    ipv6_url = url + "/drop_v6.json"
    asn_url = url + "/asndrop.json"

    @classmethod
    def location(cls, data_type: str) -> str:
        if data_type == "ipv4":
            db_name = "drop_v4.json"
        elif data_type == "ipv6":
            db_name = "drop_v6.json"
        elif data_type == "asn":
            db_name = "asndrop.json"
        else:
            raise AnalyzerRunException(f"Invalid data_type: {data_type}")
        return f"{settings.MEDIA_ROOT}/{db_name}"

    def run(self):
        if self.observable_classification == Classification.IP:
            ip = ipaddress.ip_address(self.observable_name)
            data_type = "ipv4" if ip.version == 4 else "ipv6"
            logger.info(f"The given observable ({self.observable_name}) is an {data_type} address.")
        elif self.observable_classification == Classification.GENERIC and self.observable_name.isdigit():
            data_type = "asn"
            asn = int(self.observable_name)  # Convert to integer
            logger.info(f"The given observable ({self.observable_name}) is an ASN: {asn}")
        else:
            raise AnalyzerRunException(f"Invalid observable: {self.observable_name}")

        database_location = self.location(data_type)

        if not os.path.exists(database_location):
            logger.info(f"Database does not exist in {database_location}, initialising...")
            self.update()
        with open(database_location, "r") as f:
            db = json.load(f)

        matches = []

        if data_type in ["ipv4", "ipv6"]:
            # IP Matching
            insertion = bisect.bisect_left(
                db, ip, key=lambda x: ipaddress.ip_network(x["cidr"]).network_address
            )

            for i in range(insertion, len(db)):
                network = ipaddress.ip_network(db[i]["cidr"])
                if ip in network:
                    matches.append(db[i])
                elif network.network_address > ip:
                    break
        elif data_type == "asn":
            # ASN Matching
            for entry in db[:-1]:
                if int(entry["asn"]) == asn:
                    matches.append(entry)
        else:
            raise AnalyzerRunException(f"Invalid data_type: {data_type}")

        if matches:
            return {"found": True, "details": matches}

        return {"found": False}

    @classmethod
    def update(cls):
        data_types = ["ipv4", "ipv6", "asn"]
        for data_type in data_types:
            if data_type == "ipv4":
                logger.info(f"Updating database from {cls.ipv4_url}")
                db_url = cls.ipv4_url
            elif data_type == "ipv6":
                logger.info(f"Updating database from {cls.ipv6_url}")
                db_url = cls.ipv6_url
            elif data_type == "asn":
                logger.info(f"Updating database from {cls.asn_url}")
                db_url = cls.asn_url
            else:
                raise AnalyzerRunException(f"Invalid data_type provided to update: {data_type}")
            response = requests.get(url=db_url)
            response.raise_for_status()
            data = cls.convert_to_json(response.text)
            database_location = cls.location(data_type)
            with open(database_location, "w", encoding="utf-8") as f:
                json.dump(data, f)
            logger.info(f"Database updated at {database_location}")

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
                raise AnalyzerRunException("Invalid JSON format in the response while updating the database")

        return json_objects
