import logging
import requests
import time

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers.classes import ObservableAnalyzer
from intel_owl import secrets


logger = logging.getLogger(__name__)


class InQuest(ObservableAnalyzer):
    base_url: str = "https://labs.inquest.net"
    max_tries: int = 10
    poll_distance: int = 10

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get(
            "api_key_name", "INQUEST_API_KEY"
        )
        self.__api_key = secrets.get_secret(self.api_key_name)
        self.analysis_type = additional_config_params.get("inquest_analysis", "dfi_search")
        self.observable_classification = additional_config_params.get("inquest_analysis", "details")

    def run(self):
        result = {}
        headers = {"Content-Type": "application/json"}
        if not self.__api_key:
            params = ""
            warning = f"No API key retrieved with name: {self.api_key_name}"
            logger.info(
                f"{warning}. Continuing without API key..." f" <- {self.__repr__()}"
            )
            self.report["errors"].append(warning)
        else:
            params = f"&key={self.__api_key}"

        if self.analysis_type == "dfi_search":
            if self.observable_classification == "hash":
                uri = f"/api/dfi/search/hash/md5?hash={self.observable_name}"
            elif self.observable_classification in ["ip", "url", "domain"]:
                uri = f"/api/dfi/search/ioc/{self.observable_classification}?keyword={self.observable_name}"
            else:
                raise AnalyzerRunException()

        elif self.analysis_type == "iocdb_search":
            uri = f"/api/iocdb/search?keyword={self.observable_name}"

        elif self.analysis_type == "repdb_search":
            uri = f"/api/repdb/search?keyword={self.observable_name}"
        
        try:
            response = requests.get(self.base_url + uri, params=params, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()

        return result