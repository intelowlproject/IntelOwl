# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class IPQuery(classes.ObservableAnalyzer):
    url: str = "https://api.ipquery.io/"

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        logger.info(f"Running IPQuery Analyzer for {self.observable_name}")

        try:
            response = requests.get(f"{self.url}{self.observable_name}?format=json")
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        results = response.json()
        return results
