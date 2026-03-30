# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests
from django.db import transaction

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import StratosphereIPEntry

logger = logging.getLogger(__name__)


class Stratos(classes.ObservableAnalyzer):
    base_url = "https://mcfp.felk.cvut.cz"
    mid_url = "/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/"
    priority_url = "AIP_historical_blacklist_prioritized_by_"

    lists = {
        "last24hrs": base_url + mid_url + "AIP_blacklist_for_IPs_seen_last_24_hours.csv",
        "new_attacker": base_url + mid_url + priority_url + "newest_attackers.csv",
        "repeated_attacker": base_url + mid_url + priority_url + "repeated_attackers.csv",
    }

    def run(self):
        if not StratosphereIPEntry.objects.exists():
            logger.info("StratosphereIPEntry table is empty, triggering update...")
            if not self.update():
                raise AnalyzerRunException("Failed to update Stratosphere datasets")

        ip = self.observable_name
        result = {
            "last24hrs_rating": "",
            "new_attacker_rating": "",
            "repeated_attacker_rating": "",
        }

        qs = StratosphereIPEntry.objects.filter(ip=ip)
        for entry in qs:
            key = f"{entry.list_type}_rating"
            if key in result:
                result[key] = entry.rating or "found"

        return result

    @classmethod
    def update(cls) -> bool:
        logger.info("starting download of dataset from stratosphere")

        entries_to_create = []

        try:
            for list_type, url in cls.lists.items():
                # Dataset website certificates are not correctly configured.
                response = requests.get(url, verify=False)  # lgtm [py/request-without-cert-validation]
                response.raise_for_status()

                lines = response.content.decode("utf-8").split("\n")

                # Formats vary:
                # - 'attacker' (1 column: IP)
                # - 'ip,score' (2 columns: IP, rating)
                for line in lines[1:]:  # skip header
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    split_tuple = line.split(",")
                    ip = split_tuple[0].strip()
                    rating = split_tuple[1].strip() if len(split_tuple) >= 2 else "found"

                    try:
                        rating = f"{float(rating):.3f}"
                    except (ValueError, TypeError):
                        pass

                    entries_to_create.append(StratosphereIPEntry(ip=ip, list_type=list_type, rating=rating))

            with transaction.atomic():
                StratosphereIPEntry.objects.all().delete()
                StratosphereIPEntry.objects.bulk_create(
                    entries_to_create,
                    batch_size=1000,
                    ignore_conflicts=True,
                )

            logger.info(f"Updated {len(entries_to_create)} StratosphereIPEntry entries")
            return True

        except Exception as e:
            logger.exception(f"Stratosphere failed to update: {e}")
            return False
