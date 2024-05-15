# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class Ip2location(classes.ObservableAnalyzer):
    url: str = "https://api.ip2location.io/"
    _api_key_name: str
    api_version: str

    @classmethod
    def update(cls) -> bool:
        pass

    def get_response(self, payload):
        return requests.get(self.url, params=payload)

    def run(self):
        try:
            payload = {"ip": self.observable_name}

            # There are two free versions of the service:
            #    1. keyless : Requires No API key and has a daily limit of 500 queries
            #    2. keyed: Requires API key.

            if self.api_version == "keyed":
                payload["key"] = self._api_key_name

            location_info = self.get_response(payload)
            location_info.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        response = location_info.json()
        return response

    @classmethod
    def _monkeypatch(cls):
        sample_response = {
            "ip": "8.8.8.8",
            "country_code": "US",
            "country_name": "United States of America",
            "region_name": "California",
            "city_name": "Mountain View",
            "latitude": 37.405992,
            "longitude": -122.078515,
            "zip_code": "94043",
            "time_zone": "-07:00",
            "asn": "15169",
            "as": "Google LLC",
            "is_proxy": False,
        }

        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(sample_response, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
