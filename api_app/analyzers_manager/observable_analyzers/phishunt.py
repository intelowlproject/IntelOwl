# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes


class Phishunt(classes.ObservableAnalyzer):
    """
    Wrapper for Phishunt.io.

    Phishunt provides information about known phishing domains,
    URLs and IP addresses.
    """

    url = "https://phishunt.io/api/v1/search.json"

    def update(self):
        pass

    def run(self):
        observable = self.observable_name

        # Phishunt expects only the hostname when searching for a URL.
        if self.observable_classification == "url":
            observable = urlparse(observable).hostname

        response = requests.get(
            self.url,
            params={"q": observable},
            timeout=30,
        )
        response.raise_for_status()

        data = response.json()
        results = data.get("results", [])

        exact_matches = []

        for result in results:
            if self.observable_classification == "ip":
                if result.get("ip") == observable:
                    exact_matches.append(result)
            else:
                if result.get("domain") == observable:
                    exact_matches.append(result)

        return {
            "found": bool(exact_matches),
            "results": exact_matches,
        }
