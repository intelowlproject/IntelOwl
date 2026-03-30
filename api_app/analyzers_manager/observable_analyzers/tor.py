# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import re

import requests
from django.db import transaction

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.models import TorExitNode

logger = logging.getLogger(__name__)


class Tor(classes.ObservableAnalyzer):
    url: str = "https://check.torproject.org/exit-addresses"

    def run(self):
        if not TorExitNode.objects.exists():
            logger.info("TorExitNode table is empty, triggering update...")
            self.update()
        found = TorExitNode.objects.filter(ip=self.observable_name).exists()
        return {"found": found}

    @classmethod
    def update(cls) -> bool:
        try:
            logger.info("starting download of db from tor project")
            response = requests.get(cls.url)
            response.raise_for_status()

            unique_ips = set(
                re.findall(
                    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                    response.content.decode(),
                )
            )

            with transaction.atomic():
                TorExitNode.objects.all().delete()
                TorExitNode.objects.bulk_create(
                    [TorExitNode(ip=ip) for ip in unique_ips],
                    batch_size=1000,
                    ignore_conflicts=True,
                )

            logger.info(f"Updated {len(unique_ips)} TorExitNode entries")
            return True
        except Exception as e:
            logger.exception(e)

        return False
