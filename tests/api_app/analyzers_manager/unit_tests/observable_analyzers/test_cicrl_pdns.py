import datetime
from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.observable_analyzers.circl_pdns import CIRCL_PDNS
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class CIRCLPDNSTestCase(BaseAnalyzerTest):
    analyzer_class = CIRCL_PDNS

    @classmethod
    def get_extra_config(cls):
        return {
            "_pdns_credentials": "testuser|testpass",
            "split_credentials": ["testuser", "testpass"],
            "domain": "example.com",
        }

    @staticmethod
    def get_mocked_response():
        return [
            patch(
                "api_app.analyzers_manager.observable_analyzers.circl_pdns.pypdns.PyPDNS",
                return_value=MagicMock(
                    query=MagicMock(
                        return_value=[
                            {
                                "rrtype": "A",
                                "rdata": "1.2.3.4",
                                "time_first": datetime.datetime(2024, 1, 1, 10, 0, 0),
                                "time_last": datetime.datetime(2024, 1, 1, 12, 0, 0),
                            }
                        ]
                    )
                ),
            )
        ]
