import logging
import requests
import time

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers.classes import ObservableAnalyzer
from intel_owl import secrets


logger = logging.getLogger(__name__)


class Pulsedive(ObservableAnalyzer):
    base_url: str = "https://pulsedive.com/api"
    max_tries: int = 10
    poll_distance: int = 10

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get(
            "api_key_name", "PULSEDIVE_API_KEY"
        )
        active_scan = additional_config_params.get("active_scan", True)
        self.probe = 1 if active_scan else 0

    def run(self):
        result = {}
        default_param = ""
        api_key = secrets.get_secret(self.api_key_name)
        if not api_key:
            warning = f"No API key retrieved with name: {self.api_key_name}"
            logger.info(
                f"{warning}. Continuing without API key..." f" <- {self.__repr__()}"
            )
            self.report["errors"].append(warning)
        else:
            default_param = f"&key={api_key}"

        # headers = {"Key": api_key, "Accept": "application/json"}
        # 1. query to info.php to check if the indicator is already in the database
        params = f"indicator={self.observable_name}"
        if api_key:
            params += default_param
        resp = requests.get(f"{self.base_url}/info.php?{params}")
        if resp.status_code == 404:
            raise AnalyzerRunException("Indicator not found")
        resp.raise_for_status()
        result = resp.json()
        e = result.get("error", None)
        if e == "Indicator not found.":
            # 2. submit new scan to analyze.php
            params = f"value={self.observable_name}&probe={self.probe}"
            if self.__api_key:
                params += default_param
            headers = {
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
            }
            resp = requests.post(
                f"{self.base_url}/analyze.php", data=params, headers=headers
            )
            resp.raise_for_status()
            qid = resp.json().get("qid", None)
            # 3. retrieve result using qid after waiting for 10 seconds
            params = f"qid={qid}"
            if self.__api_key:
                params += default_param
            result = self.__poll_for_result(params)
            if result.get("data", None):
                result = result["data"]

        return result

    def __poll_for_result(self, params):
        result = {}
        url = f"{self.base_url}/analyze.php?{params}"
        obj_repr = self.__repr__()
        for chance in range(self.max_tries):
            logger.info(
                f"polling request #{chance+1} for observable: {self.observable_name}"
                f" <- {obj_repr}"
            )
            time.sleep(self.poll_distance)
            resp = requests.get(url)
            resp.raise_for_status()
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
