import base64
import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class BasicAnalyzer(ObservableAnalyzer):
    _api_key_name: str
    url: str
    http_method: str
    auth_scheme: str
    user_agent: str
    param_key: str

    def run(self):
        headers = {"Accept": "application/json"}

        # optional API key
        if hasattr(self, "_api_key_name"):
            api_key = self._api_key_name
            if hasattr(self, "auth_scheme"):
                auth_scheme = self.auth_scheme
                if auth_scheme in [
                    "X-API-Key",
                    "API-Key",
                ]:  # key/X-Auth-Token/X-Key da aggiungere?
                    headers["X-API-Key"] = api_key
                else:
                    # Basic/Token/Bearer
                    if auth_scheme == "Basic":
                        # the API uses basic auth so we need to base64 encode the auth payload
                        api_key = base64.b64encode(self._api_key_name.encode()).decode()
                    headers["Authorization"] = f"{self.auth_scheme} {api_key}"
        else:
            warning = "No API key retrieved"
            logger.info(
                f"{warning}. Continuing without API key..." f" <- {self.__repr__()}"
            )
            self.report.errors.append(warning)

        # optional user agent
        if hasattr(self, "user_agent"):
            headers["User-Agent"] = self.user_agent

        # request
        if self.http_method == "get":
            if hasattr(self, "param_key"):
                params = {
                    self.param_key: self.observable_name,
                }
                response = requests.get(self.url, params=params, headers=headers)
            response = requests.get(self.url + self.observable_name, headers=headers)
        else:
            json_body = {
                self.param_key: self.observable_name,
            }
            response = requests.post(self.url, headers=headers, json=json_body)
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
