# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Dict

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class Netlas(classes.ObservableAnalyzer):
    url: str = "https://app.netlas.io/api/whois_ip/"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.query = self.observable_name

        self.headers = {"X-API-Key": f"{self._api_key_name}"}

        self.parameters = {"q": f"ip:{self.query}"}

    def run(self):
        try:
            response = requests.get(
                self.url, params=self.parameters, headers=self.headers
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()["items"][0]["data"]
        return result

    @classmethod
    def _monkeypatch(cls):
        example_response = {
            "items": [
                {
                    "data": {
                        "@timestamp": "2023-07-06T14:53:32",
                        "ip": {"gte": "8.8.8.0", "lte": "8.8.8.255"},
                        "related_nets": [
                            {
                                "country": "US",
                                "address": "1600 Amphitheatre Parkway",
                                "city": "Mountain View",
                                "created": "2014-03-14",
                                "range": "8.8.8.0 - 8.8.8.255",
                                "description": "Google LLC",
                                "handle": "NET-8-8-8-0-1",
                                "organization": "Google LLC (GOGL)",
                                "name": "LVLT-GOGL-8-8-8",
                                "start_ip": "8.8.8.0",
                                "cidr": ["8.8.8.0/24"],
                                "net_size": 255,
                                "state": "CA",
                                "postal_code": "94043",
                                "updated": "2014-03-14",
                                "end_ip": "8.8.8.255",
                            }
                        ],
                        "net": {
                            "country": "US",
                            "address": "100 CenturyLink Drive",
                            "city": "Monroe",
                            "created": "1992-12-01",
                            "range": "8.0.0.0 - 8.127.255.255",
                            "description": "Level 3 Parent, LLC",
                            "handle": "NET-8-0-0-0-1",
                            "organization": "Level 3 Parent, LLC (LPL-141)",
                            "name": "LVLT-ORG-8-8",
                            "start_ip": "8.0.0.0",
                            "cidr": ["8.0.0.0/9"],
                            "net_size": 8388607,
                            "state": "LA",
                            "postal_code": "71203",
                            "updated": "2018-04-23",
                            "end_ip": "8.127.255.255",
                        },
                        "asn": {
                            "number": ["15169"],
                            "registry": "arin",
                            "country": "US",
                            "name": "GOOGLE",
                            "cidr": "8.8.8.0/24",
                            "updated": "1992-12-01",
                        },
                    }
                }
            ],
            "took": 8,
            "timestamp": 1691652090,
        }

        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(example_response, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
