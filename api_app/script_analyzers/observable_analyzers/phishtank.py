import requests
import logging
from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers.classes import ObservableAnalyzer
from intel_owl import secrets
import base64

logger = logging.getLogger(__name__)


class Phishtank(ObservableAnalyzer):
    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get(
            "api_key_name", "PHISHTANK_API_KEY"
        )

    def run(self):
        result = {}
        headers = {"User-Agent": "phishtank/IntelOwl"}
        data = {
            "url": base64.b64encode(self.observable_name.encode("utf-8")),
            "format": "json",
        }
        api_key = secrets.get_secret(self.api_key_name)
        if not api_key:
            logger.warning(f"{self.__repr__()} -> Continuing w/o API key..")
        else:
            data["app_key"] = api_key
        try:
            resp = requests.post(
                "https://checkurl.phishtank.com/checkurl/", data=data, headers=headers
            )
            resp.raise_for_status()
            result = resp.json()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        return result
