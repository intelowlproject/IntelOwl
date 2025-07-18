from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.spamhaus_drop import SpamhausDropV4
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class SpamhausDropV4TestCase(BaseAnalyzerTest):
    analyzer_class = SpamhausDropV4

    @staticmethod
    def get_mocked_response():
        mock_data = (
            '{"cidr": "1.10.16.0/20", "sblid": "SBL256894", "rir": "apnic"}\n'
            '{"cidr": "2.56.192.0/19", "sblid": "SBL459831", "rir": "ripencc"}\n'
            '{"asn": 6517, "rir": "arin", "domain": "zeromist.net", "cc": "US", "asname": "ZEROMIST-AS-1"}\n'
            '{"cidr": "2001:678:738::/48", "sblid": "SBL635837", "rir": "ripencc"}'
        )
        return patch(
            "requests.get",
            return_value=MockUpResponse(mock_data, 200),
        )
