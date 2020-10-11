import re
import requests

from api_app.script_analyzers import classes


class Fortiguard(classes.ObservableAnalyzer):
    baseurl: str = "https://www.fortiguard.com/webfilter?q="

    def run(self):
        pattern = re.compile(r"(?:Category: )([\w\s]+)")
        url = self.baseurl + self.observable_name
        response = requests.get(url)
        response.raise_for_status()

        category_match = re.search(pattern, str(response.content), flags=0)
        dict_response = {"category": category_match.group(1) if category_match else ""}
        return dict_response
