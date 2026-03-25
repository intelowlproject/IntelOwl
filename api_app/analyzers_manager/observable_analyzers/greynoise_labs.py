# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import os

from django.conf import settings
from greynoiselabs import GreyNoiseLabs

from api_app.analyzers_manager.classes import ObservableAnalyzer

logger = logging.getLogger(__name__)

# This matches the storage location used by IntelOwl for local DBs
db_name = "topc2s_ips.txt"
db_location = os.path.join(settings.MEDIA_ROOT, db_name)


class GreynoiseLabs(ObservableAnalyzer):
    def run(self):
        result = {}
        auth_token = self._get_auth_token()
        if not auth_token:
            self.report.errors.append("Missing GreyNoise Labs API Token")
            return result

        client = GreyNoiseLabs(api_key=auth_token)

        try:
            # 1. NoiseRank
            noise_rank = client.get_noise_rank(ip=self.observable_name)
            result["noiserank"] = noise_rank if noise_rank else {"found": False}

            # 2. TopKnocks
            top_knocks = client.get_knocks(ip=self.observable_name)
            result["topknocks"] = top_knocks if top_knocks else {"found": False}

            # 3. TopC2s (Local DB Check)
            if not os.path.isfile(db_location) and not self.update():
                logger.error("Failed to update TopC2s database")

            if os.path.isfile(db_location):
                with open(db_location, encoding="utf-8") as f:
                    db_list = f.read().splitlines()
                result["topc2s"] = {"found": self.observable_name in db_list}

        except Exception as e:
            error_text = str(e).strip() or "Unknown GreyNoise Labs API Error"
            self.report.errors.append(error_text)
            logger.error("GreyNoise Labs Error: %s", error_text)

        return result

    def update(self):
        auth_token = self._get_auth_token()
        if auth_token:
            return self._update_db(auth_token)
        return False

    @classmethod
    def _update_db(cls, auth_token: str):
        client = GreyNoiseLabs(api_key=auth_token)
        try:
            logger.info("Fetching Top C2s from GreyNoise Labs SDK...")
            c2_data = client.get_c2s()
            if c2_data:
                with open(db_location, "w", encoding="utf-8") as f:
                    for entry in c2_data:
                        ip = entry.get("source_ip")
                        if ip:
                            f.write(f"{ip}\n")
                return True
            return False
        except Exception as e:
            logger.exception("Failed to update GreyNoise Labs DB: %s", e)
            return False
