import base64
from tempfile import NamedTemporaryFile

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.constants import HTTPMethods
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


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
        # optional authentication
        if hasattr(self, "_api_key_name") and "Authorization" in self.headers.keys():
            api_key = self._api_key_name
            auth_schema = self.headers["Authorization"].split(" ")[0]
            if auth_schema == "Basic":
                # the API uses basic auth so we need to base64 encode the auth payload
                api_key = base64.b64encode(self._api_key_name.encode()).decode()
            self.headers["Authorization"] = self.headers["Authorization"].replace(
                "<api_key>", api_key
            )
        elif hasattr(self, "_api_key_name"):
            for key in self.headers.keys():
                self.headers[key] = self.headers[key].replace(
                    "<api_key>", self._api_key_name
                )

        # optional certificate
        verify = True  # defualt
        if hasattr(self, "_certificate"):
            self.__cert_file = NamedTemporaryFile(mode="w")
            self.__cert_file.write(self._clean_certificate(self._certificate))
            self.__cert_file.flush()
            verify = self.__cert_file.name

        # replace <observable> placheholder
        if hasattr(self, "params"):
            for key in self.params.keys():
                if self.params[key] == "<observable>":
                    self.params[key] = self.observable_name

        # validate url
        if not hasattr(self, "url"):
            raise AnalyzerConfigurationException("Instance URL is required")

        # request
        if self.http_method not in HTTPMethods.values:
            raise AnalyzerConfigurationException("Http method is not valid")
        if self.http_method == HTTPMethods.GET:
            if hasattr(self, "params"):
                response = requests.get(
                    self.url, params=self.params, headers=self.headers, verify=verify
                )
            response = requests.get(
                self.url + self.observable_name, headers=self.headers, verify=verify
            )
        else:
            request_method = getattr(requests, self.http_method)
            response = request_method(
                self.url, headers=self.headers, json=self.params, verify=verify
            )
        response.raise_for_status()
        return response.json()

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
