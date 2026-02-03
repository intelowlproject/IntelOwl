# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.choices import Classification
from api_app.helpers import get_hash_type

logger = logging.getLogger(__name__)


class GreedyBear(ObservableAnalyzer):
    _api_key_name: str
    url: str
    command_sequence_toggle: bool = False
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

        if self.observable_classification == Classification.HASH:
            if get_hash_type(self.observable_name) == "sha-256":
                if self.same_cluster_commands:
                    params_["include_similar"] = True
                logger.info(f"Fetching command sequence for SHA-256 hash: {self.observable_name}.")
                command_sequence_response = requests.get(
                    self.url + command_sequence_uri, params=params_, headers=headers
                )
                result = {"command_sequence_results": command_sequence_response.json()}
            else:
                result = {"command_sequence_results": "Unsupported hash type. Only SHA-256 is supported."}
        else:
            enrichment_response = requests.get(self.url + enrichment_uri, params=params_, headers=headers)
            if self.command_sequence_toggle:
                logger.info(f"Fetching command sequence for observable: {self.observable_name}.")
                if self.same_cluster_commands:
                    params_["include_similar"] = True
                command_sequence_response = requests.get(
                    self.url + command_sequence_uri, params=params_, headers=headers
                )
                result["command_sequence_results"] = command_sequence_response.json()
                result["enrichment_results"] = enrichment_response.json()
                return result

            result = enrichment_response.json()

        return result
