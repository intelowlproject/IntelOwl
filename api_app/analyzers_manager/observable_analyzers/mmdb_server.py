import logging

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class MmdbServer(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for the mmdb-server project.
    """

    def update(self) -> bool:
        pass

    url: str
    observable_name: str

    def run(self):
        response = requests.get(self.url + self.observable_name)
        response.raise_for_status()
        return response.json()

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
