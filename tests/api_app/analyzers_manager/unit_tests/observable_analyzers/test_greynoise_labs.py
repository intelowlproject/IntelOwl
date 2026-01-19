from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.greynoise_labs import GreynoiseLabs
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class GreynoiseLabsTestCase(BaseAnalyzerTest):
    analyzer_class = GreynoiseLabs

    @classmethod
    def get_extra_config(cls):
        return {"_auth_token": "demo_token", "report": {"errors": []}}

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.post",
            side_effect=[
                MockUpResponse(
                    {
                        "data": {
                            "noiseRank": {
                                "queryInfo": {
                                    "resultsAvailable": 1,
                                    "resultsLimit": 1,
                                },
                                "ips": [
                                    {
                                        "ip": "20.235.249.22",
                                        "noise_score": 12,
                                        "sensor_pervasiveness": "very low",
                                        "country_pervasiveness": "low",
                                        "payload_diversity": "very low",
                                        "port_diversity": "very low",
                                        "request_rate": "low",
                                    }
                                ],
                            }
                        }
                    },
                    200,
                ),
                MockUpResponse(
                    {
                        "data": {
                            "topKnocks": {
                                "queryInfo": {
                                    "resultsAvailable": 1,
                                    "resultsLimit": 1,
                                },
                                "knock": {
                                    "last_crawled": "2024-01-01T00:00:00Z",
                                    "last_seen": "2024-01-02T00:00:00Z",
                                    "source_ip": "20.235.249.22",
                                    "knock_port": 22,
                                },
                            }
                        }
                    },
                    200,
                ),
                MockUpResponse(
                    {
                        "data": {
                            "topC2s": {
                                "queryInfo": {
                                    "resultsAvailable": 3,
                                    "resultsLimit": 3,
                                },
                                "c2s": [
                                    {
                                        "source_ip": "91.92.247.12",
                                        "c2_ips": ["103.245.236.120"],
                                        "c2_domains": [],
                                        "hits": 11608,
                                    },
                                    {
                                        "source_ip": "14.225.208.190",
                                        "c2_ips": ["14.225.213.142"],
                                        "c2_domains": [],
                                        "hits": 2091,
                                    },
                                ],
                            }
                        }
                    },
                    200,
                ),
            ],
        )
