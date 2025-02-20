# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class IPQuery(classes.ObservableAnalyzer):
    url: str = "https://api.ipquery.io/"

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        logger.info(f"Running IPQuery Analyzer for {self.observable_name}")

        try:
            response = requests.get(f"{self.url}{self.observable_name}?format=json")
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        results = response.json()
        return results

    @classmethod
    def _monkeypatch(cls):
        response = {
            "ip": "1.1.1.1",
            "isp": {
                "asn": "AS13335",
                "isp": "Cloudflare, Inc.",
                "org": "Cloudflare, Inc.",
            },
            "risk": {
                "is_tor": "false",
                "is_vpn": "false",
                "is_proxy": "false",
                "is_mobile": "false",
                "risk_score": 0,
                "is_datacenter": "true",
            },
            "location": {
                "city": "Sydney",
                "state": "New South Wales",
                "country": "Australia",
                "zipcode": "1001",
                "latitude": -33.854548400186665,
                "timezone": "Australia/Sydney",
                "localtime": "2025-02-03T13:06:16",
                "longitude": 151.20016200912815,
                "country_code": "AU",
            },
        }
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(response, 200),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
