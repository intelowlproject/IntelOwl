# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)


class SSAPINet(classes.ObservableAnalyzer):
    url: str = "https://shot.screenshotapi.net/screenshot"

    _api_key_name: str
    use_proxy: bool
    proxy: str
    output: str
    # for other params provided by the API
    extra_api_params: dict

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        if self.use_proxy and not self.proxy:
            raise AnalyzerConfigurationException("No proxy retrieved when use_proxy is true.")
        if self.output not in ["image", "json"]:
            raise AnalyzerConfigurationException("output param can only be 'image' or 'json'")

        try:
            if isinstance(self.extra_api_params, dict):
                params = self.extra_api_params
            else:
                params = {}
            params["url"] = self.observable_name
            params["token"] = self._api_key_name
            params["output"] = self.output

            if self.use_proxy:
                params["proxy"] = self.proxy

            resp = requests.get(self.url, params=params)
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
