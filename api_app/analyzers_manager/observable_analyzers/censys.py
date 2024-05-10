# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class Censys(classes.ObservableAnalyzer):
    """
    Censys search analyzer class. Analyzes IP addresses.
    Ugraded api endpoint v2
    Please apply secreats using: https://search.censys.io/account/api
    """

    def update(self):
        pass

    url = "https://search.censys.io/api/v2"

    censys_analysis: str
    _api_id_name: str
    _api_secret_name: str

    def run(self):
        if self.censys_analysis == "search":
            uri = f"/hosts/{self.observable_name}"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}."
                "Supported is IP"
            )
        response = requests.get(
            self.url + uri,
            auth=(self._api_id_name, self._api_secret_name),
            headers={
                "Accept": "application/json",
            },
        )
        response.raise_for_status()

        return response.json()

    @classmethod
    def _monkeypatch(cls):
        response = {
            "code": 200,
            "status": "OK",
            "result": {
                "ip": "190.121.56.10",
                "services": [],
                "location": {
                    "continent": "South America",
                    "country": "Chile",
                    "country_code": "CL",
                    "city": "Osorno",
                    "postal_code": "5290000",
                    "timezone": "America/Santiago",
                    "province": "Los Lagos Region",
                    "coordinates": {
                        "latitude": -40.57395,
                        "longitude": -73.13348,
                    },
                },
                "location_updated_at": "2024-01-27T14:52:11.775086600Z",
                "autonomous_system": {
                    "asn": 14117,
                    "description": "Telefonica del Sur S.A.",
                    "bgp_prefix": "190.121.56.0/21",
                    "name": "Telefonica del Sur S.A.",
                    "country_code": "CL",
                },
                "autonomous_system_updated_at": "2024-01-27T14:52:11.775086600Z",
                "last_updated_at": "2023-04-30T00:04:14.886Z",
            },
        }
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        response,
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
