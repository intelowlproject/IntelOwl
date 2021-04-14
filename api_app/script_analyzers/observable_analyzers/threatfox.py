import requests
import json

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes


class ThreatFox(classes.ObservableAnalyzer):
    base_url: str = "https://threatfox-api.abuse.ch/api/v1/"

    def run(self):
        payload = {
            "query": "search_ioc",
        }

        try:
            payload["search_term"] = self.observable_name
            response = requests.post(self.base_url, data=json.dumps(payload))
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        return result
