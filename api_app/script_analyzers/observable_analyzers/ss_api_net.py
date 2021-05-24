# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests
import base64

from api_app.exceptions import AnalyzerRunException, AnalyzerConfigurationException
from api_app.script_analyzers import classes
from intel_owl import secrets


class SSAPINet(classes.ObservableAnalyzer):
    base_url: str = "https://screenshotapi.net/api/v1/screenshot"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "SSAPINET_KEY")
        self.__api_key = secrets.get_secret(self.api_key_name)
        self.use_proxy = additional_config_params.get("use_proxy", False)
        if self.use_proxy:
            self.proxy = additional_config_params.get("proxy", "")
        self.output = additional_config_params.get("output", "image")
        # for other params provided by the API
        self.extra_api_params = additional_config_params.get("extra_api_params", {})

    def run(self):
        if not self.__api_key:
            raise AnalyzerConfigurationException(
                f"No API key retrieved with name: {self.api_key_name}."
            )
        if self.use_proxy and not self.proxy:
            raise AnalyzerConfigurationException(
                "No proxy retrieved when use_proxy is true."
            )
        if self.output not in ["image", "json"]:
            raise AnalyzerConfigurationException(
                "output param can only be 'image' or 'json'"
            )

        try:
            if isinstance(self.extra_api_params, dict):
                params = self.extra_api_params
            else:
                params = {}
            params["url"] = self.observable_name
            params["token"] = self.__api_key
            params["output"] = self.output

            if self.use_proxy:
                params["proxy"] = self.proxy

            resp = requests.get(self.base_url, params=params)
            resp.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        if self.output == "image":
            try:
                b64_img = base64.b64encode(resp.content).decode("utf-8")
                return {"screenshot": b64_img}
            except Exception as err:
                raise AnalyzerRunException(f"Failed to convert to base64 string {err}")
        return resp.json()
