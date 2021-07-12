# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager import classes
from ..serializers.AnalyzerConfigSerializer import ObservableTypes


class EmailRep(classes.ObservableAnalyzer):
    base_url: str = "https://emailrep.io/{}"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        """
        API key is not mandatory, emailrep supports requests with no key:
        a valid key let you to do more requests per day.
        therefore we're not checking if a key has been configured.
        """

        headers = {
            "User-Agent": "IntelOwl v2",
            "Key": self.__api_key,
            "Accept": "application/json",
        }

        if self.observable_classification not in [ObservableTypes.GENERIC.value]:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}."
                f" Supported: generic"
            )

        url = self.base_url.format(self.observable_name)

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()
