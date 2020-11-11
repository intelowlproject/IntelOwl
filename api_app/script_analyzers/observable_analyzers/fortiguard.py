import re
import requests

from urllib.parse import urlparse

from api_app.script_analyzers import classes


class Fortiguard(classes.ObservableAnalyzer):
    baseurl: str = "https://www.fortiguard.com/webfilter?q="

    def run(self):
        observable = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == "url":
            observable = urlparse(self.observable_name).hostname
        pattern = re.compile(r"(?:Category: )([\w\s]+)")
        url = self.baseurl + observable
        response = requests.get(url)
        response.raise_for_status()

        category_match = re.search(pattern, str(response.content), flags=0)
        dict_response = {"category": category_match.group(1) if category_match else ""}
        return dict_response
