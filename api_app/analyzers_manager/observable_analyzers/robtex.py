# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class Robtex(classes.ObservableAnalyzer):
    base_url = "https://freeapi.robtex.com/"

    def set_params(self, params):
        self.analysis_type = params.get("robtex_analysis", "ip_query")

    def run(self):
        if self.analysis_type == "ip_query":
            uri = f"ipquery/{self.observable_name}"
        elif self.analysis_type == "reverse_pdns":
            uri = f"pdns/reverse/{self.observable_name}"
        elif self.analysis_type == "forward_pdns":
            domain = self.observable_name
            if self.observable_classification == self.ObservableTypes.URL:
                domain = urlparse(self.observable_name).hostname
            uri = f"pdns/forward/{domain}"
        else:
            raise AnalyzerRunException(
                f"not supported analysis type {self.analysis_type}."
            )
        try:
            response = requests.get(self.base_url + uri)
            response.raise_for_status()
            result = response.text.split("\r\n")
        except requests.ConnectionError as e:
            raise AnalyzerRunException(f"Connection error: {e}")
        else:
            loaded_results = []
            for item in result:
                if len(item) > 0:
                    loaded_results.append(json.loads(item))

        return loaded_results

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse(
                        {}, 200, text='{"test1":"test1"}\r\n{"test2":"test2"}'
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
