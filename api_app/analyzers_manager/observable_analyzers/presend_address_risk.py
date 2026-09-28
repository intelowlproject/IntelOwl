# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import re

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification


class PresendAddressRisk(ObservableAnalyzer):
    """
    This analyzer checks an EVM address against the OFAC sanctions list.
    """

    url: str = "https://presend.pages.dev/api/address-risk"

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        if self.observable_classification != Classification.GENERIC:
            raise AnalyzerRunException("Invalid observable classification")

        if not re.match(r"^0x[a-fA-F0-9]{40}$", self.observable_name):
            raise AnalyzerRunException("Invalid EVM address")

        params = {"address": self.observable_name}

        try:
            response = requests.get(self.url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
