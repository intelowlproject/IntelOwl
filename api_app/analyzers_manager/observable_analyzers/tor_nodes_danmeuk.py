# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests
from django.db import transaction

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.models import TorDanMeUKNode

logger = logging.getLogger(__name__)


class TorNodesDanMeUK(classes.ObservableAnalyzer):
    url: str = "https://www.dan.me.uk/torlist/?full"

    def run(self):
        if not TorDanMeUKNode.objects.exists():
            logger.info("TorDanMeUKNode table is empty, triggering update...")
            self.update()
        result = {"found": False}
        if TorDanMeUKNode.objects.filter(ip=self.observable_name).exists():
            result["found"] = True
            result["nodes_info"] = self.url
        return result

    @classmethod
    def update(cls) -> bool:
        try:
            logger.info("starting download of tor nodes from https://dan.me.uk")
            response = requests.get(cls.url)
            response.raise_for_status()

            unique_ips = {ip for ip in response.content.decode().split("\n") if ip.strip()}

            with transaction.atomic():
                TorDanMeUKNode.objects.all().delete()
                TorDanMeUKNode.objects.bulk_create(
                    [TorDanMeUKNode(ip=ip) for ip in unique_ips],
                    batch_size=1000,
                    ignore_conflicts=True,
                )

            logger.info(f"Updated {len(unique_ips)} TorDanMeUKNode entries")
            return True
        except Exception as e:
            logger.exception(e)

        return False
