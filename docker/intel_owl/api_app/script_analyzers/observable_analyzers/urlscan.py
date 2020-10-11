import requests
import time
import logging
from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers.classes import ObservableAnalyzer
from intel_owl import secrets


logger = logging.getLogger(__name__)


class UrlScan(ObservableAnalyzer):
    base_url: str = "https://urlscan.io/api/v1"

    def set_config(self, additional_config_params):
        self.analysis_type = additional_config_params.get("urlscan_analysis", "search")
        self.visibility = additional_config_params.get("visibility", "private")
        self.search_size = additional_config_params.get("search_size", 100)
        self.api_key_name = additional_config_params.get(
            "api_key_name", "URLSCAN_API_KEY"
        )

    def run(self):
        result = {}
        headers = {"Content-Type": "application/json", "User-Agent": "IntelOwl/v1.x"}
        api_key = secrets.get_secret(self.api_key_name)
        if not api_key:
            if self.analysis_type == "search":
                logger.warning(f"{self.__repr__()} -> Continuing w/o API key..")
            else:
                raise AnalyzerRunException(
                    f"No API key retrieved for name {self.api_key_name}."
                )
        else:
            headers["API-Key"] = api_key
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
            else:
                result = resp.json()
                break
        return result

    def __urlscan_search(self):
        result = {}
        params = {
            "q": f'{self.observable_classification}:"{self.observable_name}"',
            "size": self.search_size,
        }
        if self.observable_classification == "url":
            params["q"] = "page." + params["q"]
        try:
            resp = self.session.get(self.base_url + "/search/", params=params)
            resp.raise_for_status()
            result = resp.json()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        return result
