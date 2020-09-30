import requests
import time
from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets

max_tries: int = 10
poll_distance: int = 2


class UrlScan(classes.ObservableAnalyzer):
    base_url: str = "https://urlscan.io/"

    def set_config(self, additional_config_params):
        self.analysis_type = additional_config_params.get("urlscan_analysis", "search")
        api_key_name = additional_config_params.get("api_key_name", "URLSCAN_API_KEY")
        self.visibility = additional_config_params.get("visibility", "public")
        self.__api_key = secrets.get_secret(api_key_name)

    def __submit_query(self):
        data = {"url": self.observable_name, "visibility": self.visibility}
        uri = "api/v1/scan/"
        try:
            response = self.session.post(self.base_url + uri, json=data)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        return response.json()["api"]

    def __poll_for_result(self, url):
        result = {}
        for chance in range(max_tries):
            time.sleep(poll_distance)
            resp = self.session.get(url)
            if resp.status_code == 404:
                continue
            else:
                result = resp.json()
                break
        return result

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException("no api key retrieved")
        headers = {
            "Content-Type": "application/json",
            "API-Key": self.__api_key,
        }
        self.session = requests.Session()
        self.session.headers = headers
        if self.analysis_type == "search":
            params = {
                "q": f'{self.observable_classification}:"{self.observable_name}"',
                "size": 100,
            }
            if self.observable_classification == "url":
                params["q"] = "page." + params["q"]

            uri = "api/v1/search/"
            try:
                response = self.session.get(self.base_url + uri, params=params)
                response.raise_for_status()
                result = response.json()
            except requests.RequestException as e:
                raise AnalyzerRunException(e)

        elif self.analysis_type == "submit_result":
            token = self.__submit_query()
            result = self.__poll_for_result(token)
        else:
            raise AnalyzerRunException(
                "not supported analysis_type"
                f" {self.analysis_type}."
                "Supported is 'search' and 'submit_result'."
            )
        return result
