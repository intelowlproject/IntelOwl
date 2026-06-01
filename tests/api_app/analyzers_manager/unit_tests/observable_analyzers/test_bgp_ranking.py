from types import SimpleNamespace
from unittest.mock import patch

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers import bgp_ranking as bgp_ranking_module
from api_app.analyzers_manager.observable_analyzers.bgp_ranking import BGPRanking
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class BGPRankingTestCase(BaseAnalyzerTest):
    analyzer_class = BGPRanking

    def test_run_raises_clean_exception_on_empty_asn_history(self):
        # An IP with no ASN history returns an empty "response" object. The
        # analyzer must raise a clean AnalyzerRunException instead of crashing
        # with "KeyError: 'popitem(): dictionary is empty'". The analyzer is
        # built with a stand-in config so the test runs deterministically and is
        # not skipped when no AnalyzerConfig is loaded in the DB.
        analyzer = BGPRanking(SimpleNamespace(name="BGPRanking"))
        analyzer.observable_name = "8.8.8.8"
        analyzer.url = "https://bgp-ranking.circl.lu"
        analyzer.timeout = 30
        with (
            patch.object(
                bgp_ranking_module.requests,
                "get",
                return_value=MockUpResponse({"meta": {"ip": "8.8.8.8"}, "response": {}}, 200),
            ),
            self.assertRaises(AnalyzerRunException),
        ):
            analyzer.run()

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
