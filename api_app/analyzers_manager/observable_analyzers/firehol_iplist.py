# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import ipaddress
import logging
import os
import traceback
from datetime import datetime

import requests
from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)

logger = logging.getLogger(__name__)

db_path = f"{settings.MEDIA_ROOT}"


class FireHol_IPList(classes.ObservableAnalyzer):
    list_names: list

    def run(self):
        ip = self.observable_name
        result = {}

        if not self.list_names:
            raise AnalyzerConfigurationException(
                "list_names is empty in custom analyzer config, add an iplist"
            )

        for list_name in self.list_names:
            result[list_name] = False

            self.check_iplist_status(list_name)

            with open(f"{db_path}/{list_name}", "r", encoding="utf-8") as f:
                db = f.read()

            db_list = db.split("\n")

            for ip_or_subnet in db_list:
                if ip_or_subnet and ipaddress.ip_address(ip) in ipaddress.ip_network(ip_or_subnet):
                    result[list_name] = True
                    break

        return result

    @staticmethod
    def download_iplist(list_name):
        if ".ipset" not in list_name and ".netset" not in list_name:
            raise AnalyzerConfigurationException(
                f"extension missing from {list_name} (add .ipset or .netset to name)"
            )

        try:
            iplist_location = f"{db_path}/{list_name}"
            data_cleaned = ""

            logger.info(f"starting download of {list_name} from firehol iplist")
            url = f"https://iplists.firehol.org/files/{list_name}"
            r = requests.get(url)
            r.raise_for_status()

            data_extracted = r.content.decode()

            for line in data_extracted.splitlines():
                if not line.startswith("#"):
                    data_cleaned += f"{line}\n"

            with open(iplist_location, "w", encoding="utf-8") as f:
                f.write(data_cleaned)

            if not os.path.exists(iplist_location):
                raise AnalyzerRunException(f"failed extraction of {list_name} iplist")

            logger.info(f"ended download of {list_name} from firehol iplist")

        except Exception as e:
            traceback.print_exc()
            logger.exception(e)

    def check_iplist_status(self, list_name):
        iplist_location = f"{db_path}/{list_name}"

        if not os.path.exists(iplist_location):
            self.download_iplist(list_name)

        now = datetime.now()
        timestamp = os.path.getctime(iplist_location)
        dt_object = datetime.fromtimestamp(timestamp)
        time_diff = now - dt_object

        if time_diff.days < 1:
            logger.info("iplist is up to date")
        else:
            os.remove(iplist_location)
            self.download_iplist(list_name)
