from urllib.parse import quote

from api_app import http_utils
from api_app.analyzers_manager import classes


class MalprobSearch(classes.ObservableAnalyzer):
    url: str = "https://malprob.io/api"

    def update(self):
        pass

    def run(self):
        response = http_utils.get(
            f"{self.url}/search/{quote(self.observable_name, safe='')}",
            timeout=10,
        )
        response.raise_for_status()
        return response.json()
