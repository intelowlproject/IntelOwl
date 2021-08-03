# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes

from tests.mock_utils import if_mock_connections, patch, MockResponse


class MB_GET(classes.ObservableAnalyzer):
    url: str = "https://mb-api.abuse.ch/api/v1/"
    sample_url: str = "https://bazaar.abuse.ch/sample/"

    def run(self):
        post_data = {"query": "get_info", "hash": self.observable_name}

        response = requests.post(self.url, data=post_data)
        response.raise_for_status()

        result = response.json()
        result_data = result.get("data", [])
        if result_data and isinstance(result_data, list):
            sha256 = result_data[0].get("sha256_hash", "")
            if sha256:
                result["permalink"] = f"{self.sample_url}{sha256}"

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse({"data": [{"sha256_hash": "test"}]}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
