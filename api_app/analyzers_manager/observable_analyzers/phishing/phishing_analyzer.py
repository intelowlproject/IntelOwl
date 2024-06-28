from logging import getLogger
from typing import Dict
from unittest.mock import patch

import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By  # noqa: F401
from selenium.webdriver.common.keys import Keys  # noqa: F401

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections

logger = getLogger(__name__)


class PhishingAnalyzer(ObservableAnalyzer):
    proxy_protocol: str = ""
    proxy_address: str = ""
    proxy_port: str = ""

    driver: webdriver.Chrome = None

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        options: Options = None
        if self.proxy_address and self.proxy_protocol and self.proxy_port:
            options = self._config_proxy_server()
        self.driver = webdriver.Chrome(options=options)

    def _config_proxy_server(self) -> Options:
        options = webdriver.ChromeOptions()
        options.add_argument(
            f"--proxy-server={self.proxy_protocol}://"
            f"{self.proxy_address}:{self.proxy_port}"
        )
        options.add_argument(
            f'--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE {self.proxy_address}"'
        )
        options.add_argument(
            "--remote-debugging-pipe"
        )  # due to https://github.com/SeleniumHQ/selenium/issues/12841
        return options

    def run(self):
        self.driver.get(self.observable_name)

        response = requests.get(
            url=self.observable_name,
            proxies=f"{self.proxy_protocol}://"
            f"{self.proxy_address}:{self.proxy_port}",
            timeout=20,
        )
        response.raise_for_status()
        if response.status_code == 404:
            return {"not_found": True}

        html_page: str = self.driver.page_source

        self.driver.close()

        return {
            "page_source": html_page,
            "text_response": response.text,
            "request_body": response.request.body.encode("utf-8"),
            "request_headers": response.request.headers,
        }

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
