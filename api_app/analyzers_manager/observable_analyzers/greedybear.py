# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from ipaddress import ip_address

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class GreedyBear(ObservableAnalyzer):
    _api_key_name: str
    url: str
    command_sequence_toggle: bool = True
    same_cluster_commands: bool = False

    def is_ip_address(self, observable: str) -> bool:
        try:
            ip_address(observable)
            return True
        except ValueError:
            return False

    def is_sha256_hash(self, observable: str) -> bool:
        return len(observable) == 64 and all(
            c in "0123456789abcdefABCDEF" for c in self.observable_name
        )

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

        if self.is_sha256_hash(self.observable_name):
            if self.same_cluster_commands:
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
                result["command_sequence_results"] = command_sequence_response.json()

            enrichment_response = requests.get(
                self.url + enrichment_uri, params=params_, headers=headers
            )
            result["enrichment_results"] = enrichment_response.json()

        return result

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
