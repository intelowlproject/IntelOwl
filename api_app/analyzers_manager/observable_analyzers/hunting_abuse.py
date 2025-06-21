# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class HuntingAbuseAPI(ObservableAnalyzer):
    url: str = "https://hunting-api.abuse.ch/api/v1/"
    _auth_key: str

    @classmethod
    def update(cls):
        pass

    def run(self):
        headers = {"Content-Type": "application/json", "Auth-Key": self._auth_key}

        data = {"query": "get_fplist", "format": "json"}

        response = requests.post(self.url, json=data, headers=headers)
        response.raise_for_status()
        fp_list = response.json()

        for _key, value_dict in fp_list.items():
            logger.info(f"Fetching fp_status for {self.observable_name}")
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
