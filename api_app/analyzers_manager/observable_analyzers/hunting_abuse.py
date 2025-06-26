# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


import json
import logging
import os

import requests

# from analyzers_manager.models import AnalyzerConfig
from django.conf import settings

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.models import PluginConfig
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)

db_name = "hunting_abuse_fplist.json"
database_location = f"{settings.MEDIA_ROOT}/{db_name}"


class HuntingAbuseAPI(ObservableAnalyzer):
    url: str = "https://hunting-api.abuse.ch/api/v1/"
    _auth_key: str

    @classmethod
    def get_auth_key(cls) -> str | None:
        for plugin in PluginConfig.objects.filter(
            parameter__python_module=cls.python_module,
            parameter__is_secret=True,
            parameter__name="auth_key",
        ):
            if plugin.value:
                return plugin.value
        return None

    @classmethod
    def update(cls) -> bool:
        auth_key = cls.get_auth_key()
        headers = {"Content-Type": "application/json", "Auth-Key": auth_key}
        data = {"query": "get_fplist", "format": "json"}

        try:
            response = requests.post(cls.url, json=data, headers=headers)
            response.raise_for_status()

            with open(database_location, "w", encoding="utf-8") as f:
                f.write(response.text)

            if not os.path.exists(database_location):
                raise Exception(f"database location {database_location} does not exist")
            return True
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
            if value_dict["entry_value"] == self.observable_name:
                return {"fp_status": "true", "details": value_dict}
        return {"fp_status": "False"}

    @classmethod
    def _monkeypatch(cls):
        mock_response = {
            "1": {
                "time_stamp": "2025-06-04 07:46:14 UTC",
                "platform": "MalwareBazaar",
                "entry_type": "sha1_hash",
                "entry_value": "ac4cb655a78a5634f6a87c82bec33a4391269a3f",
                "removed_by": "admin",
                "removal_notes": None,
            }
        }
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse(mock_response, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches)
