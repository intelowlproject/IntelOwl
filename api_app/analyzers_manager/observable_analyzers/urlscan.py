# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class UrlScan(ObservableAnalyzer):
    base_url: str = "https://urlscan.io/api/v1"

    def set_params(self, params):
        self.analysis_type = params.get("urlscan_analysis", "search")
        self.visibility = params.get("visibility", "private")
        self.search_size = params.get("search_size", 100)
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        result = {}
        headers = {"Content-Type": "application/json", "User-Agent": "IntelOwl/v1.x"}
        if not self.__api_key and self.analysis_type == "search":
            logger.warning(f"{self.__repr__()} -> Continuing w/o API key..")
        else:
            headers["API-Key"] = self.__api_key

        self.session = requests.Session()
        self.session.headers = headers
        if self.analysis_type == "search":
            result = self.__urlscan_search()
        elif self.analysis_type == "submit_result":
            req_api_token = self.__urlscan_submit()
            result = self.__poll_for_result(req_api_token)
        else:
            raise AnalyzerRunException(
                f"not supported analysis_type {self.analysis_type}."
                " Supported is 'search' and 'submit_result'."
            )
        return result

    def __urlscan_submit(self) -> str:
        data = {"url": self.observable_name, "visibility": self.visibility}
        uri = "/scan/"
        try:
            response = self.session.post(self.base_url + uri, json=data)
            # catch error description to help users to understand why it did not work
            if response.status_code == 400:
                error_description = response.json().get("description", "")
                raise requests.HTTPError(error_description)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
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
        result = {}
        params = {
            "q": f'{self.observable_classification}:"{self.observable_name}"',
            "size": self.search_size,
        }
        if self.observable_classification == self.ObservableTypes.URL:
            params["q"] = "page." + params["q"]
        try:
            resp = self.session.get(self.base_url + "/search/", params=params)
            resp.raise_for_status()
            result = resp.json()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.post",
                    return_value=MockResponse({"api": "test"}, 200),
                ),
                patch("requests.Session.get", return_value=MockResponse({}, 200)),
            )
        ]
        return super()._monkeypatch(patches=patches)
