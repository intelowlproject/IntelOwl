# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class MnemonicPassiveDNS(classes.ObservableAnalyzer):
    base_url: str = "https://api.mnemonic.no/pdns/v3/"

    def set_params(self, params):
        self._cofformat = params.get("cof_format", True)
        self._limit = params.get("limit", 100)

    def run(self):
        if self._cofformat:
            self.base_url += "cof/"
        try:
            response = requests.get(
                self.base_url + self.observable_name, data={"limit": self._limit}
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        if self._cofformat:
            result = [json.loads(line) for line in response.text.splitlines()]

        else:
            result = response.json()

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
