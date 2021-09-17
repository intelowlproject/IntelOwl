# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager import classes

from tests.mock_utils import if_mock_connections, patch, MockResponse


class GreyNoise(classes.ObservableAnalyzer):
    base_url: str = "https://api.greynoise.io"

    def set_params(self, params):
        self.api_version = params.get("greynoise_api_version", "v3")
        self.max_records_to_retrieve = int(params.get("max_records_to_retrieve", 500))

    def run(self):
        if self.api_version == "v1":
            url = f"{self.base_url}/v1/query/ip"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {"ip": self.observable_name}
            response = requests.post(url, data=data, headers=headers)
            response.raise_for_status()

        elif self.api_version == "v2":
            url = f"{self.base_url}/v2/noise/context/{self.observable_name}"
            # API key is mandatory
            api_key = self._secrets["api_key_name"]
            headers = {"Accept": "application/json", "key": api_key}
            response = requests.get(url, headers=headers)
            response.raise_for_status()

        elif self.api_version == "v3":
            url = f"{self.base_url}/v3/community/{self.observable_name}"
            headers = {"Accept": "application/json"}
            # optional usage of API key
            api_key = self._secrets["api_key_name"]
            if api_key:
                headers["key"] = api_key
            response = requests.get(url, headers=headers)
            if response.status_code != 404:
                response.raise_for_status()

        else:
            raise AnalyzerRunException(
                "Invalid API Version. "
                "Supported are: v1 (alpha), v2 (paid), v3 (community)"
            )

        result = response.json()
        if "records" in result:
            result["records"] = result["records"][: self.max_records_to_retrieve]

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse({}, 200),
                ),
                patch(
                    "requests.post",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
