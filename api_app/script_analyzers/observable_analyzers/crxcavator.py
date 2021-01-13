import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes


class CRXcavator(classes.ObservableAnalyzer):
    name: str = "CRXcavator"
    base_url: str = "https://api.crxcavator.io/v1/report/"

    def run(self):
        try:
            response = requests.get(self.base_url + self.observable_name)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        return result
