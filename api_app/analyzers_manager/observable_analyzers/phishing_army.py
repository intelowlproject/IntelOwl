# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from urllib.parse import urlparse

import requests
from django.db import transaction

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.models import PhishingArmyDomain
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class PhishingArmy(classes.ObservableAnalyzer):
    url = "https://phishing.army/download/phishing_army_blocklist.txt"

    def run(self):
        if not PhishingArmyDomain.objects.exists():
            logger.info("PhishingArmyDomain table is empty, triggering update...")
            self.update()

        to_analyze_observable = self.observable_name
        if self.observable_classification == Classification.URL:
            to_analyze_observable = urlparse(self.observable_name).hostname

        found = PhishingArmyDomain.objects.filter(domain=to_analyze_observable).exists()
        return {"found": found, "link": self.url}

    @classmethod
    def update(cls) -> bool:
        try:
            logger.info("starting download of db from Phishing Army")
            response = requests.get(cls.url)
            response.raise_for_status()

            unique_domains = {
                domain
                for domain in response.content.decode().split("\n")
                if domain.strip() and not domain.startswith("#")
            }

            with transaction.atomic():
                PhishingArmyDomain.objects.all().delete()
                PhishingArmyDomain.objects.bulk_create(
                    [PhishingArmyDomain(domain=domain) for domain in unique_domains],
                    batch_size=1000,
                    ignore_conflicts=True,
                )

            logger.info(f"Updated {len(unique_domains)} PhishingArmyDomain entries")
            return True
        except Exception as e:
            logger.exception(e)

        return False
