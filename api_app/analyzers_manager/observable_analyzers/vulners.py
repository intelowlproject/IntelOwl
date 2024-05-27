import logging

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class Vulners(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for the vulners project.
    """

    score_AI: bool = False
    skip: int = 0
    size: int = 5
    _api_key_name: str
    url = "https://vulners.com/api/v3"

    def search_ai(self):
        return requests.post(
            url=self.url + "/ai/scoretext/",
            headers={"Content-Type": "application/json"},
            json={"text": self.observable_name, "apiKey": self._api_key_name},
        )

    def search_databse(self):
        return requests.post(
            url=self.url + "/search/lucene",
            headers={"Content-Type": "application/json"},
            json={
                "query": self.observable_name,
                "skip": self.size,
                "size": self.skip,
                "apiKey": self._api_key_name,
            },
        )

    def run(self):
        response = None
        if self.score_AI:
            response = self.search_ai()
        else:
            response = self.search_databse()
        response.raise_for_status()
        return response.json()

    # this is a framework implication
    def update(self) -> bool:
        pass

    @classmethod
    def _monkeypatch(cls):
        response = {"result": "OK", "data": {"score": [6.5, "NONE"]}}
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse(response, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
