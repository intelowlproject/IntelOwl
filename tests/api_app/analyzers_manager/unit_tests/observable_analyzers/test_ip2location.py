from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.ip2location import Ip2location
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class Ip2locationTestCase(BaseAnalyzerTest):
    analyzer_class = Ip2location

    @staticmethod
    def get_mocked_response():
        mock_response = {
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

        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "dummy_key", "api_version": "keyed"}
