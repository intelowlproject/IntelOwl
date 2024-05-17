import logging

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class HudsonRock(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for hudson rock
    """

    compromised_since: str
    compromised_until: str
    _api_key_name: str

    url = "https://cavalier.hudsonrock.com/api/json/v2"

    def run(self):
        response = {}
        headers = {
            "api-key": self._api_key_name,
            "Content-Type": "application/json",
        }
        if self.observable_classification == self.ObservableTypes.IP:
            url = self.url + "/search-by-ip"
            response = requests.post(
                url, headers=headers, json={"ip": self.observable_name}
            )

        elif self.observable_classification == self.ObservableTypes.DOMAIN:
            url = (
                self.url
                + f"/search-by-domain?compromised_since={self.compromised_since}"
                + f"&compromised_until={self.compromised_until}"
            )
            response = requests.post(
                url, headers=headers, json={"domains": [self.observable_name]}
            )

        elif self.observable_classification == self.ObservableTypes.GENERIC:
            url = self.url + "/search-by-login"
            response = requests.post(
                url, headers=headers, json={"login": self.observable_name}
            )
        else:
            raise AnalyzerConfigurationException(
                f"Invalid observable type {self.observable_classification}"
                + f"{self.observable_name} for HudsonRock"
            )
        response.raise_for_status()
        return response.json()

    def update(self) -> bool:
        pass

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "country": {"iso_code": "BE"},
                            "meta": {
                                "description": {"en": "Geo Open MMDB database"},
                                "build_db": "2022-02-05 11:37:33",
                                "db_source": "GeoOpen-Country",
                                "nb_nodes": 1159974,
                            },
                            "ip": "188.65.220.25",
                            "country_info": {
                                "Country": "Belgium",
                                "Alpha-2 code": "BE",
                                "Alpha-3 code": "BEL",
                                "Numeric code": "56",
                                "Latitude (average)": "50.8333",
                                "Longitude (average)": "4",
                            },
                        },
                        {
                            "country": {
                                "iso_code": "BE",
                                "AutonomousSystemNumber": "49677",
                                "ASO": "MAEHDROS-AS",
                            },
                            "meta": {
                                "description": {"en": "Geo Open MMDB database"},
                                "build_db": "2022-02-06 10:30:25",
                                "db_source": "GeoOpen-Country-ASN",
                                "nb_nodes": 1159815,
                            },
                            "ip": "188.65.220.25",
                            "country_info": {
                                "Country": "Belgium",
                                "Alpha-2 code": "BE",
                                "Alpha-3 code": "BEL",
                                "Numeric code": "56",
                                "Latitude (average)": "50.8333",
                                "Longitude (average)": "4",
                            },
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
