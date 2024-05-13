# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests
from django.conf import settings

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class Crowdsec(ObservableAnalyzer):
    _api_key_name: str
    url: str = "https://cti.api.crowdsec.net"

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        headers = {
            "x-api-key": self._api_key_name,
            "User-Agent": f"crowdsec-intelowl/{settings.VERSION}",
        }
        url = f"{self.url}/v2/smoke/{self.observable_name}"
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            result = {"not_found": True}
        else:
            response.raise_for_status()
            result = response.json()
        result["link"] = f"https://app.crowdsec.net/cti/{self.observable_name}"
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "behaviors": [
                                {
                                    "name": "http:exploit",
                                    "label": "HTTP Exploit",
                                    "description": "bla bla",
                                }
                            ]
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
