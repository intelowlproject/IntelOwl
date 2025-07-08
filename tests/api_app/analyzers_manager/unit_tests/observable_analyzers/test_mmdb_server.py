from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.mmdb_server import MmdbServer
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class MmdbServerTestCase(BaseAnalyzerTest):
    analyzer_class = MmdbServer

    @staticmethod
    def get_mocked_response():
        return patch(
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
                200,
            ),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"url": "https://mock-mmdb-server.local/query/"}
