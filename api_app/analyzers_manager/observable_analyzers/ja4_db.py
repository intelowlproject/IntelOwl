import json
import logging

import requests
from django.db import transaction

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.models import Ja4DBEntry

logger = logging.getLogger(__name__)


class Ja4DB(classes.ObservableAnalyzer):
    url = "https://ja4db.com/api/read/"
    fingerprint_fields = (
        "ja4_fingerprint",
        "ja4s_fingerprint",
        "ja4h_fingerprint",
        "ja4x_fingerprint",
        "ja4t_fingerprint",
        "ja4ts_fingerprint",
        "ja4tscan_fingerprint",
    )

    @classmethod
    def update(cls) -> bool:
        logger.info(f"Updating database from {cls.url}")
        response = requests.get(url=cls.url, timeout=30)
        response.raise_for_status()
        data = response.json()

        db_entries = []
        for item in data:
            for fingerprint_type in cls.fingerprint_fields:
                fingerprint_value = item.get(fingerprint_type)
                if fingerprint_value:
                    db_entries.append(
                        Ja4DBEntry(
                            fingerprint_type=fingerprint_type,
                            fingerprint_value=fingerprint_value,
                            details=item,
                        )
                    )

        with transaction.atomic():
            Ja4DBEntry.objects.all().delete()
            Ja4DBEntry.objects.bulk_create(db_entries, batch_size=1000)

        logger.info(f"Updated {len(db_entries)} JA4 DB fingerprint entries")
        return True

    def run(self):
        if not Ja4DBEntry.objects.exists():
            logger.info("Ja4DBEntry table is empty, triggering update...")
            try:
                self.update()
            except requests.RequestException as exc:
                logger.exception("Failed to update JA4 DB entries from %s: %s", self.url, exc)
                return {"error": f"Unable to update JA4 DB: {exc}"}
            except Exception as exc:
                logger.exception("Unexpected error while updating JA4 DB entries from %s: %s", self.url, exc)
                return {"error": f"Unexpected JA4 DB update failure: {exc}"}

        matches = []
        seen = set()
        for details in Ja4DBEntry.objects.filter(fingerprint_value=self.observable_name).values_list(
            "details", flat=True
        ):
            serialized = json.dumps(details, sort_keys=True)
            if serialized not in seen:
                seen.add(serialized)
                matches.append(details)
        if matches:
            return {"found": True, "results": matches}
        return {"found": False}
