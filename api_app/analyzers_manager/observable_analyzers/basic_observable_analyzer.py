import base64
import logging
from tempfile import NamedTemporaryFile

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class BasicObservableAnalyzer(ObservableAnalyzer):
    url: str
    auth_scheme: str
    user_agent: str
    param_key: str
    _certificate: str
    _api_key_name: str = None
    http_method: str = "get"

    def _get_auth_headers(self):
        auth_headers = {}
        if hasattr(self, "_api_key_name") and hasattr(self, "auth_scheme"):
            api_key = self._api_key_name
            if self.auth_scheme in [
                "X-API-Key",
                "API-Key",
                "X-Auth-Token",
                "X-Key",
                "key",
            ]:
                auth_headers[self.auth_scheme] = api_key
            else:
                # Basic/Token/Bearer
                if self.auth_scheme == "Basic":
                    # the API uses basic auth so we need to base64 encode the auth payload
                    api_key = base64.b64encode(self._api_key_name.encode()).decode()
                auth_headers["Authorization"] = f"{self.auth_scheme} {api_key}"
        else:
            warning = "No API key retrieved"
            logger.info(
                f"{warning}. Continuing without API key..." f" <- {self.__repr__()}"
            )
            self.report.errors.append(warning)
        return auth_headers

    @staticmethod
    def _clean_certificate(cert):
        return (
            cert.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN_CERTIFICATE-----")
            .replace("-----END CERTIFICATE-----", "-----END_CERTIFICATE-----")
            .replace(" ", "\n")
            .replace("-----BEGIN_CERTIFICATE-----", "-----BEGIN CERTIFICATE-----")
            .replace("-----END_CERTIFICATE-----", "-----END CERTIFICATE-----")
        )

    def run(self):
        headers = {"Accept": "application/json"}

        # optional authentication
        headers.update(self._get_auth_headers())

        # optional user agent
        if hasattr(self, "user_agent"):
            headers["User-Agent"] = self.user_agent

        # optional certificate
        verify = True
        if hasattr(self, "certificate"):
            self.__cert_file = NamedTemporaryFile(mode="w")
            self.__cert_file.write(self._clean_certificate(self._certificate))
            self.__cert_file.flush()
            verify = self.__cert_file.name

        # request
        if self.http_method == "get":
            if hasattr(self, "param_key"):
                params = {
                    self.param_key: self.observable_name,
                }
                response = requests.get(
                    self.url, params=params, headers=headers, verify=verify
                )
            response = requests.get(
                self.url + self.observable_name, headers=headers, verify=verify
            )

        if self.http_method == "post":
            json_body = {
                self.param_key: self.observable_name,
            }
            response = requests.post(
                self.url, headers=headers, json=json_body, verify=verify
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
