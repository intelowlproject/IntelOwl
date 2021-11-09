# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import re
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockResponse, if_mock_connections, patch


class Fortiguard(classes.ObservableAnalyzer):
    baseurl: str = "https://www.fortiguard.com/webfilter?q="

    def run(self):
        observable = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == self.ObservableTypes.URL:
            observable = urlparse(self.observable_name).hostname
        pattern = re.compile(r"(?:Category: )([\w\s]+)")
        url = self.baseurl + observable
        response = requests.get(url)
        response.raise_for_status()

        category_match = re.search(pattern, str(response.content), flags=0)
        dict_response = {"category": category_match.group(1) if category_match else ""}
        return dict_response

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse(
                        {}, 200, content="Category: Test Fortiguard"
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
