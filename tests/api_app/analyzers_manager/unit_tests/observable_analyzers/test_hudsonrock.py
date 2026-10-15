from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from api_app.analyzers_manager.observable_analyzers.hudsonrock import HudsonRock
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse, patch


class HudsonRockTestCase(BaseAnalyzerTest):
    analyzer_class = HudsonRock

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.get",
            return_value=MockUpResponse(
                {
                    "message": "This IP address is associated with a computer that was infected by an info-stealer.",
                    "stealers": [],
                    "total_corporate_services": 0,
                    "total_user_services": 12,
                },
                200,
            ),
        )

    def test_generic_non_email_raises_exception(self):
        """Test that non-email GENERIC observable raises AnalyzerConfigurationException."""
        analyzer = HudsonRock.__new__(HudsonRock)
        analyzer.observable_classification = "generic"
        analyzer.observable_name = "johndoe123"
        analyzer.url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"

        with self.assertRaises(AnalyzerConfigurationException) as context:
            analyzer.run()
        self.assertIn("not a valid email", str(context.exception))
