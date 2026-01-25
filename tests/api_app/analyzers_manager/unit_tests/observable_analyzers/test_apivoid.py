from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.apivoid import ApiVoidAnalyzer
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class ApiVoidAnalyzerTestCase(BaseAnalyzerTest):
    analyzer_class = ApiVoidAnalyzer

    @staticmethod
    def get_mocked_response():
        # Use the same mock response for all observable types (IP/domain/URL)
        mock_response_data = {
            "data": {
                "report": {
                    "ip": "2.57.122.0",
                    "version": "v4",
                    "blacklists": {
                        "engines": {
                            "0": {
                                "engine": "0spam",
                                "detected": False,
                                "reference": "https://0spam.org/",
                                "elapsed": "0.09",
                            },
                        },
                        "detections": 7,
                        "engines_count": 79,
                        "detection_rate": "9%",
                        "scantime": "1.35",
                    },
                    "information": {
                        "reverse_dns": "",
                        "continent_code": "EU",
                        "continent_name": "Europe",
                        "country_code": "RO",
                        "country_name": "Romania",
                        "country_currency": "RON",
                        "country_calling_code": "40",
                        "region_name": "Bucuresti",
                        "city_name": "Bucharest",
                        "latitude": 44.432301,
                        "longitude": 26.10607,
                        "isp": "Pptechnology Limited",
                        "asn": "AS47890",
                    },
                    "anonymity": {
                        "is_proxy": False,
                        "is_webproxy": False,
                        "is_vpn": False,
                        "is_hosting": False,
                        "is_tor": False,
                    },
                    "risk_score": {"result": 100},
                }
            },
            "credits_remained": 24.76,
            "estimated_queries": "309",
            "elapsed_time": "2.58",
            "success": True,
        }

        return patch(
            "requests.post",
            return_value=type(
                "MockResponse",
                (),
                {
                    "json": lambda self: mock_response_data,
                    "raise_for_status": lambda self: None,
                    "status_code": 200,
                },
            )(),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key": "dummy_api_key_for_testing",
        }
