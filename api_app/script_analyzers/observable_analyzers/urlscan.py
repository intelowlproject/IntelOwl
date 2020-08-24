import requests
import time
from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class UrlScan(classes.ObservableAnalyzer):
    base_url: str = "https://urlscan.io/"

    def set_config(self, additional_config_params):
        self.analysis_type = additional_config_params.get("urlscan_analysis", "search")
        api_key_name = additional_config_params.get("api_key_name", "URLSCAN_KEY")
        self.visibility = additional_config_params.get("visibility", "public")
        self.__api_key = secrets.get_secret(api_key_name)

    def __submit_query(self):
        data = {"url": self.observable_name, "visibility": self.visibility}
        uri = "api/v1/scan/"
        try:
            response = requests.post(
                self.base_url + uri, headers=self.headers, json=data
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        return response.json()["api"]

    def __poll_for_result(self, url, headers):
        max_tries: int = 10
        poll_distance: int = 2
        result = {}
        for chance in range(max_tries):
            time.sleep(poll_distance)
            resp = requests.get(url, headers=headers)
            resp_json = resp.json()
            status = resp_json.get("status", None)
            if status == "done":
                result = resp_json
                break
            elif status == "processing":
                continue
            else:
                err = resp_json.get("error", "Report not found.")
                raise AnalyzerRunException(err)
        return result

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException("no api key retrieved")
        else:
            self.headers = {
                "API-Key": self.__api_key,
                "Content-Type": "application/json",
            }

        if self.analysis_type == "search":
            params = {"q": f"{self.observable_classification}:{self.observable_name}", "size": 100}
            uri = "api/v1/search/"
            try:
                response = requests.get(
                    self.base_url + uri, params=params, headers=self.headers
                )
                response.raise_for_status()
                result = response.json()
            except requests.RequestException as e:
                raise AnalyzerRunException(e)

        elif self.analysis_type == "submit_result":
            token = self.__submit_query()
            time.sleep(10)
            result = self.__poll_for_result(token, self.headers)
        else:
            raise AnalyzerRunException(
                "not supported analysis_type"
                f" {self.analysis_type}."
                "Supported is 'search' and 'submit_result'."
            )

        return result
