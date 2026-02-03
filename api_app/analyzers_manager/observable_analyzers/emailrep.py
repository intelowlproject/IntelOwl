# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification


class EmailRep(classes.ObservableAnalyzer):
    url: str = "https://emailrep.io/{}"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        """
        API key is not mandatory, emailrep supports requests with no key:
        a valid key let you to do more requests per day.
        therefore we're not checking if a key has been configured.
        """

        headers = {
            "User-Agent": "IntelOwl",
            "Key": self._api_key_name,
            "Accept": "application/json",
        }

        if self.observable_classification not in [Classification.GENERIC]:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}. Supported: generic"
            )

        url = self.url.format(self.observable_name)

        response = requests.get(url, headers=headers)
        response.raise_for_status()

        return response.json()
