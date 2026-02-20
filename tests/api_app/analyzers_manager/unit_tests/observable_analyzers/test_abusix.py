from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.abusix import Abusix
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class AbusixTestCase(BaseAnalyzerTest):
    analyzer_class = Abusix

    @staticmethod
    def get_mocked_response():
        return patch(
            "querycontacts.ContactFinder.find",
            return_value=["network-abuse@google.com"],
        )
