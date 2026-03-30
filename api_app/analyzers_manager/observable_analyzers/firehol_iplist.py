# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import ipaddress
import logging
import traceback

import requests
from django.db import transaction
from django.utils import timezone

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.analyzers_manager.models import FireholIPEntry

logger = logging.getLogger(__name__)


class FireHol_IPList(classes.ObservableAnalyzer):
    list_names: list

    def run(self):
        ip_str = self.observable_name
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise AnalyzerRunException(f"Invalid IP address: {ip_str}")

        result = {}

        if not self.list_names:
            raise AnalyzerConfigurationException(
                "list_names is empty in custom analyzer config, add an iplist"
            )

        for list_name in self.list_names:
            result[list_name] = False

            self.check_iplist_status(list_name)

            qs = FireholIPEntry.objects.filter(list_name=list_name).values_list("ip_or_subnet", flat=True)

            for ip_or_subnet in qs:
                if ip_or_subnet:
                    try:
                        network = ipaddress.ip_network(ip_or_subnet)
                        if ip in network:
                            result[list_name] = True
                            break
                    except ValueError:
                        pass

        return result

    @classmethod
    def update(cls, list_name=None):
        if list_name is None:
            list_names = set(FireholIPEntry.objects.values_list("list_name", flat=True))
            for ln in list_names:
                cls.update(ln)
            return

        if ".ipset" not in list_name and ".netset" not in list_name:
            raise AnalyzerConfigurationException(
                f"extension missing from {list_name} (add .ipset or .netset to name)"
            )

        try:
            logger.info(f"starting download of {list_name} from firehol iplist")
            url = f"https://iplists.firehol.org/files/{list_name}"
            r = requests.get(url)
            r.raise_for_status()

            data_extracted = r.content.decode()
            db_entries = []

            for line in data_extracted.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        network = ipaddress.ip_network(line)
                        nw_addr = str(network.network_address)
                        db_entries.append(
                            FireholIPEntry(
                                list_name=list_name,
                                ip_or_subnet=line,
                                network_address=nw_addr,
                            )
                        )
                    except ValueError:
                        pass

            if not db_entries:
                logger.warning(f"No valid IPs found in {list_name}")
                return

            with transaction.atomic():
                FireholIPEntry.objects.filter(list_name=list_name).delete()
                FireholIPEntry.objects.bulk_create(db_entries, batch_size=1000, ignore_conflicts=True)

            logger.info(
                f"ended download of {list_name} from firehol iplist, inserted {len(db_entries)} entries"
            )

        except Exception as e:
            traceback.print_exc()
            logger.exception(e)

    def check_iplist_status(self, list_name):
        first_entry = FireholIPEntry.objects.filter(list_name=list_name).first()

        if not first_entry:
            self.update(list_name)
            return

        now = timezone.now()
        time_diff = now - first_entry.updated_at

        if time_diff.days >= 1:
            self.update(list_name)
