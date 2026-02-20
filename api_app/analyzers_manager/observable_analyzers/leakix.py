import logging

import requests

from api_app.analyzers_manager import classes

logger = logging.getLogger(__name__)


class LeakIx(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for LeakIx API.
    """

    def update(self) -> bool:
        pass

    url: str = "https://leakix.net/host"
    _api_key: str = ""

    def run(self):
        headers = {"api-key": f"{self._api_key}", "Accept": "application/json"}
        response = requests.get(url=self.url + f"/{self.observable_name}", headers=headers)
        response.raise_for_status()
        return response.json()
