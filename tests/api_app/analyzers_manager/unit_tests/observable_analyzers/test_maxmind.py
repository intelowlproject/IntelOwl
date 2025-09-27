# tests/api_app/analyzers_manager/unit_tests/observable_analyzers/test_maxmind.py

from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.maxmind import Maxmind
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class MaxmindTestCase(BaseAnalyzerTest):
    analyzer_class = Maxmind

    @staticmethod
    def get_mocked_response():
        return patch.object(
            Maxmind,
            "run",
            return_value={
                "autonomous_system_number": 15169,
                "autonomous_system_organization": "Google LLC",
                "country": {"iso_code": "US", "names": {"en": "United States"}},
            },
        )
