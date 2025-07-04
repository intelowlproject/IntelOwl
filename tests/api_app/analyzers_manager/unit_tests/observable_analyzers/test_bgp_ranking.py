from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.bgp_ranking import BGPRanking
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class BGPRankingTestCase(BaseAnalyzerTest):
    analyzer_class = BGPRanking

    @staticmethod
    def get_mocked_response():
        return [
            patch(
                "requests.get",
                return_value=MockUpResponse(
                    {
                        "meta": {"ip": "8.8.8.8"},
                        "response": {
                            "2024-03-07T12:00:00": {
                                "asn": "15169",
                                "prefix": "8.8.8.0/24",
                                "source": "caida",
                            }
                        },
                    },
                    200,
                ),
            ),
            patch(
                "requests.post",
                side_effect=[
                    # First POST request - ASN ranking
                    MockUpResponse(
                        {
                            "meta": {"asn": "15169"},
                            "response": {
                                "asn_description": "GOOGLE, US",
                                "ranking": {
                                    "rank": 0.0001234567890123456,
                                    "position": 1500,
                                    "total_known_asns": 15000,
                                },
                            },
                        },
                        200,
                    ),
                    # Second POST request - ASN history (only if period is set)
                    MockUpResponse(
                        {
                            "meta": {"asn": "15169", "period": 7},
                            "response": {
                                "asn_history": [
                                    ["2024-03-01", 0.0001234567890123456],
                                    ["2024-03-02", 0.0001123456789012345],
                                    ["2024-03-03", 0.0001345678901234567],
                                ]
                            },
                        },
                        200,
                    ),
                ],
            ),
        ]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "url": "https://bgp-ranking.circl.lu",
            "timeout": 30,
            "period": 7,
        }
