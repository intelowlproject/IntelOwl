# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class UrlScan(ObservableAnalyzer):
    url: str = "https://urlscan.io/api/v1"

    urlscan_analysis: str
    visibility: str
    search_size: int
    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        headers = {"Content-Type": "application/json", "User-Agent": "IntelOwl/v1.x"}
        if not hasattr(self, "_api_key_name") and self.urlscan_analysis == "search":
            logger.warning(f"{self.__repr__()} -> Continuing w/o API key..")
        else:
            headers["API-Key"] = self._api_key_name

        self.session = requests.Session()
        self.session.headers = headers
        if self.urlscan_analysis == "search":
            result = self.__urlscan_search()
        elif self.urlscan_analysis == "submit_result":
            req_api_token = self.__urlscan_submit()
            result = self.__poll_for_result(req_api_token)
        else:
            raise AnalyzerRunException(
                f"not supported analysis_type {self.urlscan_analysis}."
                " Supported is 'search' and 'submit_result'."
            )
        return result

    def __urlscan_submit(self) -> str:
        data = {"url": self.observable_name, "visibility": self.visibility}
        uri = "/scan/"
        response = self.session.post(self.url + uri, json=data)
        # catch error description to help users to understand why it did not work
        if response.status_code == 400:
            error_description = response.json().get("description", "")
            raise requests.HTTPError(error_description)
        response.raise_for_status()
        return response.json().get("api", "")

    def __poll_for_result(self, url):
        # docs: "The most efficient approach would be to wait at least 10 seconds
        # before starting to poll, and then only polling 2-second intervals with an
        # eventual upper timeout in case the scan does not return."
        max_tries = 10
        poll_distance = 2
        result = {}
        time.sleep(10)
        for chance in range(max_tries):
            if chance:
                time.sleep(poll_distance)
            resp = self.session.get(url)
            if resp.status_code == 404:
                continue
            result = resp.json()
            break
        return result

    def __urlscan_search(self):
        params = {
            "q": f'{self.observable_classification}:"{self.observable_name}"',
            "size": self.search_size,
        }
        if self.observable_classification == Classification.URL:
            params["q"] = "page." + params["q"]
        resp = self.session.get(self.url + "/search/", params=params)
        resp.raise_for_status()
        result = resp.json()
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.post",
                    return_value=MockUpResponse({"api": "test"}, 200),
                ),
                patch("requests.Session.get", return_value=MockUpResponse({}, 200)),
            )
        ]
        return super()._monkeypatch(patches=patches)
