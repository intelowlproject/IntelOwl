# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import base64
import logging
from tempfile import NamedTemporaryFile

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.constants import HTTPMethods
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)

logger = logging.getLogger(__name__)


class BasicObservableAnalyzer(ObservableAnalyzer):
    url: str
    headers: dict
    params: dict
    _certificate: str
    _api_key_name: str
    http_method: str = "get"

    @staticmethod
    def _clean_certificate(cert):
        return (
            cert.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN_CERTIFICATE-----")
            .replace("-----END CERTIFICATE-----", "-----END_CERTIFICATE-----")
            .replace(" ", "\n")
            .replace("-----BEGIN_CERTIFICATE-----", "-----BEGIN CERTIFICATE-----")
            .replace("-----END_CERTIFICATE-----", "-----END CERTIFICATE-----")
        )

    def update(self) -> bool:
        pass

    def run(self):
        if not hasattr(self, "url"):
            raise AnalyzerConfigurationException("Instance URL is required")
        if self.http_method not in HTTPMethods.values:
            raise AnalyzerConfigurationException("Http method is not valid")

        # replace <observable> placheholder
        for key in self.params.keys():
            if self.params[key] == "<observable>":
                self.params[key] = self.observable_name

        # optional authentication
        if hasattr(self, "_api_key_name") and self._api_key_name:
            api_key = self._api_key_name
            if (
                "Authorization" in self.headers.keys()
                and self.headers["Authorization"].split(" ")[0] == "Basic"
            ):
                # the API uses basic auth so we need to base64 encode the auth payload
                api_key = base64.b64encode(self._api_key_name.encode()).decode()
            # replace <api_key> placeholder
            for key in self.headers.keys():
                self.headers[key] = self.headers[key].replace("<api_key>", api_key)

        # optional certificate
        verify = True  # defualt
        if hasattr(self, "_certificate") and self._certificate:
            self.__cert_file = NamedTemporaryFile(mode="w")
            self.__cert_file.write(self._clean_certificate(self._certificate))
            self.__cert_file.flush()
            verify = self.__cert_file.name

        try:
            if self.http_method == HTTPMethods.GET:
                url = self.url
                if not self.params.keys():
                    url = self.url + self.observable_name
                response = requests.get(
                    url,
                    params=self.params,
                    headers=self.headers,
                    verify=verify,
                )
            else:
                request_method = getattr(requests, self.http_method)
                response = request_method(self.url, headers=self.headers, json=self.params, verify=verify)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        response_json = response.json()
        logger.debug(f"response received: {response_json}")
        return response_json
