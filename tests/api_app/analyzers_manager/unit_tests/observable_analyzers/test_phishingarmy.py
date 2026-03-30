from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.observable_analyzers.phishing_army import PhishingArmy
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class PhishingArmyTestCase(BaseAnalyzerTest):
    analyzer_class = PhishingArmy

    @staticmethod
    def get_mocked_response():
        return [
            patch(
                "api_app.analyzers_manager.observable_analyzers.phishing_army.PhishingArmyDomain.objects",
                **{
                    "exists.return_value": True,
                    "filter.return_value": MagicMock(exists=MagicMock(return_value=True)),
                    "all.return_value": MagicMock(delete=MagicMock()),
                    "bulk_create.return_value": [],
                },
            ),
        ]
