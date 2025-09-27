import requests

from api_app.analyzers_manager import classes


class MalprobSearch(classes.ObservableAnalyzer):
    url: str = "https://malprob.io/api"

    def update(self):
        pass

    def run(self):
        response = requests.get(
            f"{self.url}/search/{self.observable_name}",
            timeout=10,
        )
        response.raise_for_status()
        return response.json()
