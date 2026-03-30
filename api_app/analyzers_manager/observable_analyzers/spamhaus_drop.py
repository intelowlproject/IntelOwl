import bisect
import ipaddress
import json
import logging

import requests
from django.db import transaction

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import SpamhausDropItem
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class SpamhausDropV4(classes.ObservableAnalyzer):
    url = "https://www.spamhaus.org/drop"
    ipv4_url = url + "/drop_v4.json"
    ipv6_url = url + "/drop_v6.json"
    asn_url = url + "/asndrop.json"

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

        if not SpamhausDropItem.objects.exists():
            logger.info("SpamhausDrop database is empty, initialising...")
            self.update()

        matches = []

        if data_type in ["ipv4", "ipv6"]:
            # IP Matching
            qs = SpamhausDropItem.objects.filter(data_type=data_type)
            db = [item.details for item in qs]
            db.sort(key=lambda x: ipaddress.ip_network(x["cidr"]).network_address)

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
            qs_asn = SpamhausDropItem.objects.filter(data_type="asn", value=str(asn))
            for item in qs_asn:
                matches.append(item.details)
        else:
            raise AnalyzerRunException(f"Invalid data_type: {data_type}")

        if matches:
            return {"found": True, "details": matches}

        return {"found": False}

    @classmethod
    def update(cls):
        data_types = ["ipv4", "ipv6", "asn"]
        db_entries = []
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

            for item in data:
                val = item.get("cidr") if data_type in ["ipv4", "ipv6"] else item.get("asn")

                nw_addr = None
                if data_type in ["ipv4", "ipv6"] and item.get("cidr"):
                    try:
                        nw_addr = str(ipaddress.ip_network(item.get("cidr")).network_address)
                    except ValueError:
                        pass

                if val is not None:
                    db_entries.append(
                        SpamhausDropItem(
                            data_type=data_type, value=str(val), network_address=nw_addr, details=item
                        )
                    )

        with transaction.atomic():
            SpamhausDropItem.objects.all().delete()
            SpamhausDropItem.objects.bulk_create(db_entries, batch_size=1000, ignore_conflicts=True)

        logger.info(f"SpamhausDropItem database updated with {len(db_entries)} items.")

    @staticmethod
    def convert_to_json(input_string) -> list:
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
