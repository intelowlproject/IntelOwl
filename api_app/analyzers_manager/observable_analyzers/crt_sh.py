import logging

import requests

from api_app.analyzers_manager import classes

logger = logging.getLogger(__name__)


class Crt_sh(classes.ObservableAnalyzer):
    """
    Wrapper of crt.sh
    """

    url = "https://crt.sh"

    def update(self):
        pass

    def run(self):
        headers = {"accept": "application/json"}
        response = requests.get(f"{self.url}/?q={self.observable_name}", headers=headers)
        response.raise_for_status()
        response = response.json()
        return response
