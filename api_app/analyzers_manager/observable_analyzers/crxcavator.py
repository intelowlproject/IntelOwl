# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class CRXcavator(classes.ObservableAnalyzer):
    name: str = "CRXcavator"
    url: str = "https://api.crxcavator.io/v1/report/"

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        try:
            response = requests.get(self.url + self.observable_name)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        return result
