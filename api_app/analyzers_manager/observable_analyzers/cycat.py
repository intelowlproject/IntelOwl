import logging
import re

import requests

from api_app.analyzers_manager import classes

logger = logging.getLogger(__name__)


class CyCat(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for cycat api.
    """

    def update(self) -> bool:
        pass

    url: str = "https://api.cycat.org"

    def uuid_lookup(self, uuid: str):
        logger.info(f"performing lookup on uuid: {uuid}, observable: {self.observable_name}")
        response = requests.get(
            self.url + "/lookup/" + uuid,
            headers={"accept": "application/json"},
        )
        response.raise_for_status()
        return response.json()

    def run(self):
        final_response = {}
        uuid_pattern = re.compile(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            re.IGNORECASE,
        )
        if uuid_pattern.match(self.observable_name):
            final_response = self.uuid_lookup(self.observable_name)

        else:
            response = requests.get(
                self.url + "/search/" + self.observable_name,
                headers={"accept": "application/json"},
            )
            response.raise_for_status()
            response = response.json()
            for uuid in response:
                final_response[uuid] = self.uuid_lookup(uuid)
        return final_response
