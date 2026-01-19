import logging

import requests

from api_app.analyzers_manager import classes

logger = logging.getLogger(__name__)


class MmdbServer(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for the mmdb-server project.
    """

    def update(self) -> bool:
        pass

    url: str
    observable_name: str

    def run(self):
        response = requests.get(self.url + self.observable_name)
        response.raise_for_status()
        return response.json()
