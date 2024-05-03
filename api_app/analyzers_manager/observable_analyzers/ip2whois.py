# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class Ip2whois(classes.ObservableAnalyzer):
    base_url: str = "https://api.ip2whois.com/v2"
    _api_key_name: str

    def update(self):
        pass

    def get_response(self, payload):
        return requests.get(self.base_url, params=payload)

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
            "domain": "locaproxy.com",
            "domain_id": "1710914405_DOMAIN_COM-VRSN",
            "status": "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            "create_date": "2012-04-03T02:34:32Z",
            "update_date": "2021-12-03T02:54:57Z",
            "expire_date": "2024-04-03T02:34:32Z",
            "domain_age": 3863,
            "whois_server": "whois.godaddy.com",
            "registrar": {
                "iana_id": "146",
                "name": "GoDaddy.com, LLC",
                "url": "https://www.godaddy.com"
            },
            "registrant": {
                "name": "Registration Private",
                "organization": "Domains By Proxy, LLC",
                "street_address": "DomainsByProxy.com",
                "city": "Tempe",
                "region": "Arizona",
                "zip_code": "85284",
                "country": "US",
                "phone": "+1.4806242599",
                "fax": "+1.4806242598",
                "email": "Select Contact Domain Holder link at https://www.godaddy.com/whois/results.aspx?domain=LOCAPROXY.COM"
            },
            "admin": {
                "name": "Registration Private",
                "organization": "Domains By Proxy, LLC",
                "street_address": "DomainsByProxy.com",
                "city": "Tempe",
                "region": "Arizona",
                "zip_code": "85284",
                "country": "US",
                "phone": "+1.4806242599",
                "fax": "+1.4806242598",
                "email": "Select Contact Domain Holder link at https://www.godaddy.com/whois/results.aspx?domain=LOCAPROXY.COM"
            },
            "tech": {
                "name": "Registration Private",
                "organization": "Domains By Proxy, LLC",
                "street_address": "DomainsByProxy.com",
                "city": "Tempe",
                "region": "Arizona",
                "zip_code": "85284",
                "country": "US",
                "phone": "+1.4806242599",
                "fax": "+1.4806242598",
                "email": "Select Contact Domain Holder link at https://www.godaddy.com/whois/results.aspx?domain=LOCAPROXY.COM"
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
                "email": ""
            },
            "nameservers": ["vera.ns.cloudflare.com", "walt.ns.cloudflare.com"]
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
