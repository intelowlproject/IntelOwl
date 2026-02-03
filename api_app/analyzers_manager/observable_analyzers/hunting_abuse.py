# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


import json
import logging
import os

import requests
from django.conf import settings

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from api_app.mixins import AbuseCHMixin
from api_app.models import PluginConfig

logger = logging.getLogger(__name__)

db_name = "hunting_abuse_fplist.json"
database_location = f"{settings.MEDIA_ROOT}/{db_name}"


class HuntingAbuseAPI(AbuseCHMixin, ObservableAnalyzer):
    url: str = "https://hunting-api.abuse.ch/api/v1/"

    def _do_create_data_model(self) -> bool:
        return super()._do_create_data_model() and self.report.report.get("fp_status", False)

    @classmethod
    def get_auth_key(cls) -> str:
        for plugin in PluginConfig.objects.filter(
            parameter__python_module=cls.python_module,
            parameter__is_secret=True,
            parameter__name="service_api_key",
        ):
            if plugin.value:
                return plugin.value
        return ""

    @classmethod
    def update(cls) -> bool:
        headers = {"Content-Type": "application/json", "Auth-Key": cls.get_auth_key()}
        data = {"query": "get_fplist", "format": "json"}

        try:
            response = requests.post(cls.url, json=data, headers=headers)
            response.raise_for_status()

            with open(database_location, "w", encoding="utf-8") as f:
                json.dump(response.json(), f)

            if not os.path.exists(database_location):
                raise FileNotFoundError(f"Failed to create the database file at {database_location}")
            return True

        except requests.RequestException as e:
            logger.error(f"Failed to fetch response from Hunting Abuse API: {e}")
        except FileNotFoundError as e:
            logger.error(f"File not found: {e}")
        except Exception as e:
            logger.error(f"Failed to update Hunting Abuse database: {e}")

        return False

    def run(self):
        if not os.path.isfile(database_location):
            logger.info("Hunting Abuse database not found, updating...")
            if not self.update():
                raise AnalyzerRunException("Failed extraction of Hunting Abuse db")

        with open(database_location, "r", encoding="utf-8") as f:
            fp_list = json.load(f)

        for _key, value_dict in fp_list.items():
            # Checking observable classification is IP, is necessary to handle cases where response contains
            # results in 'ip:port' format
            is_match = self.observable_name == value_dict["entry_value"] or (
                self.observable_classification == Classification.IP
                and self.observable_name in value_dict["entry_value"]
            )

            if is_match:
                return {"fp_status": True, "details": value_dict}
        return {"fp_status": False}
