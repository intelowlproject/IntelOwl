import logging

import requests

from api_app.analyzers_manager import classes
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class OrklSearch(classes.ObservableAnalyzer):
    url = "https://orkl.eu/api/v1"
    full: bool = False
    limit: int = 1000

    def update(self):
        pass

    def run(self):
        headers = {
            "accept": "application/json",
        }
        if self.observable_classification == Classification.HASH.value:
            response = requests.get(
                url=f"{self.url}/library/entry/sha1/{self.observable_name}",
                headers=headers,
            )
            if response.status_code == 404:
                return {
                    "message": "No LibraryEntry found with SHA1 hash",
                }
        else:
            response = requests.get(
                url=f"""{self.url}/library/search?query={self.observable_name}
                &full={self.full}&limit={self.limit}""",
                headers=headers,
            )

        response.raise_for_status()
        return response.json()
