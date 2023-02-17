# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockResponse, if_mock_connections, patch

from ...exceptions import AnalyzerRunException
from .vt3_base import VirusTotalv3AnalyzerMixin


class VirusTotalv3Intelligence(ObservableAnalyzer, VirusTotalv3AnalyzerMixin):
    base_url = "https://www.virustotal.com/api/v3/intelligence"

    def set_params(self, params):
        self.limit = params.get("limit", 300)
        # this is a limit forced by VT service
        if self.limit > 300:
            self.limit = 300
        self.order_by = params.get("order_by", "")

    def run(self):
        # ref: https://developers.virustotal.com/reference/intelligence-search
        params = {
            "query": self.observable_name,
            "limit": self.limit,
        }
        if self.order_by:
            params["order"] = self.order_by
        try:
            response = requests.get(
                self.base_url + "/search", params=params, headers=self.headers
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        result = response.json()
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
