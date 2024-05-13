# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class MnemonicPassiveDNS(classes.ObservableAnalyzer):
    url: str = "https://api.mnemonic.no/pdns/v3/"

    cof_format: bool
    limit: int

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        if self.cof_format:
            self.url += "cof/"
        response = requests.get(
            self.url + self.observable_name, data={"limit": self.limit}
        )
        response.raise_for_status()

        if self.cof_format:
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
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
