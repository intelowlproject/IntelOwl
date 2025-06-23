# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.helpers import get_hash_type
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class GreedyBear(ObservableAnalyzer):
    _api_key_name: str
    url: str
    command_sequence_toggle: bool
    same_cluster_commands: bool = False

    @classmethod
    def update(cls):
        pass

    def run(self):
        headers = {
            "Authorization": "Token " + self._api_key_name,
            "Accept": "application/json",
        }

        params_ = {"query": self.observable_name, "include_similar": False}

        enrichment_uri = "/api/enrichment"
        command_sequence_uri = "/api/command_sequence"

        result = {}
        try:
            if get_hash_type(self.observable_name) == "sha-256":
                params_["include_similar"] = True

                command_sequence_response = requests.get(
                    self.url + command_sequence_uri, params=params_, headers=headers
                )
                result = {"command_sequence_results": command_sequence_response.json()}

            else:
                if self.command_sequence_toggle:
                    if self.same_cluster_commands:
                        params_["include_similar"] = True
                    command_sequence_response = requests.get(
                        self.url + command_sequence_uri, params=params_, headers=headers
                    )
                    result["command_sequence_results"] = (
                        command_sequence_response.json()
                    )

                enrichment_response = requests.get(
                    self.url + enrichment_uri, params=params_, headers=headers
                )
                result["enrichment_results"] = enrichment_response.json()

            return result

        except Exception as e:
            logger.error(f"Unexpected error during GreedyBear analyzer run: {e}")
            raise AnalyzerRunException(f"Unexpected error: {e}")

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
