# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class Ip2whois(classes.ObservableAnalyzer):
    url: str = "https://api.ip2whois.com/v2"
    _api_key_name: str

    def update(self):
        pass

    def get_response(self, payload):
        return requests.get(self.url, params=payload)

    def run(self):
        try:
            params = {
                "key": self._api_key_name,
                "domain": self.observable_name,
            }

            location_info = self.get_response(params)
            location_info.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        response = location_info.json()
        return response

    @classmethod
    def _monkeypatch(cls):
        sample_response = {
            "domain": "msn.com",
            "domain_id": "4569290_DOMAIN_COM-VRSN",
            "status": "client delete prohibited",
            "create_date": "1994-11-10T05:00:00Z",
            "update_date": "2023-05-03T11:39:17Z",
            "expire_date": "2024-06-04T16:44:29Z",
            "domain_age": 10766,
            "whois_server": "",
            "registrar": {"iana_id": "292", "name": "MarkMonitor Inc.", "url": ""},
            "registrant": {
                "name": "",
                "organization": "",
                "street_address": "",
                "city": "",
                "region": "",
                "zip_code": "",
                "country": "",
                "phone": "",
                "fax": "",
                "email": "",
            },
            "admin": {
                "name": "",
                "organization": "",
                "street_address": "",
                "city": "",
                "region": "",
                "zip_code": "",
                "country": "",
                "phone": "",
                "fax": "",
                "email": "",
            },
            "tech": {
                "name": "",
                "organization": "",
                "street_address": "",
                "city": "",
                "region": "",
                "zip_code": "",
                "country": "",
                "phone": "",
                "fax": "",
                "email": "",
            },
            "billing": {
                "name": "",
                "organization": "",
                "street_address": "",
                "city": "",
                "region": "",
                "zip_code": "",
                "country": "",
                "phone": "",
                "fax": "",
                "email": "",
            },
            "nameservers": [
                "dns1.p09.nsone.net",
                "ns1-204.azure-dns.com",
                "ns2-204.azure-dns.net",
                "ns3-204.azure-dns.org",
                "ns4-204.azure-dns.info",
            ],
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
