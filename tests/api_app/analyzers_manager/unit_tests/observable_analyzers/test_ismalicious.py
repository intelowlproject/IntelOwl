# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.ismalicious import IsMalicious
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse

SAMPLE_REPORT = {
    "malicious": True,
    "riskScore": {"score": 80, "level": "high"},
    "categories": ["c2"],
    "sources": [{"name": "feed-a"}],
    "query": "8.8.8.8",
}


class IsMaliciousTestCase(BaseAnalyzerTest):
    analyzer_class = IsMalicious

    @staticmethod
    def get_mocked_response():
        return patch(
            "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
            return_value=MockUpResponse(SAMPLE_REPORT, 200),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "fake_api_key"}
