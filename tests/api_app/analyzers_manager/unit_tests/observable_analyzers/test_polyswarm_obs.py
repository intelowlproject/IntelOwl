from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.observable_analyzers.polyswarm_obs import PolyswarmObs
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class PolyswarmObsTestCase(BaseAnalyzerTest):
    analyzer_class = PolyswarmObs

    @staticmethod
    def get_mocked_response():
        # Mock PolyswarmAPI with minimal responses
        mock_api = MagicMock()

        # Mock hash search result with proper assertion objects
        mock_assertion = MagicMock()
        mock_assertion.verdict = True
        mock_assertion.engine = "test_engine"

        mock_search_result = MagicMock()
        mock_search_result.failed = False
        mock_search_result.assertions = [mock_assertion]
        mock_api.search.return_value = [mock_search_result]

        # Mock domain/IP host check
        mock_host_response = MagicMock()
        mock_host_response.json.return_value = {
            "status": "success",
            "result": {"malicious": False},
        }
        mock_api.check_known_hosts.return_value = [mock_host_response]

        return patch(
            "api_app.analyzers_manager.observable_analyzers.polyswarm_obs.PolyswarmAPI",
            return_value=mock_api,
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key": "test_key", "polyswarm_community": "default"}
