# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Dict

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

from ...exceptions import AnalyzerRunException
from .vt3_base import VirusTotalv3AnalyzerMixin


class VirusTotalv3Intelligence(ObservableAnalyzer, VirusTotalv3AnalyzerMixin):
    url = "https://www.virustotal.com/api/v3/intelligence"

    limit: int
    order_by: str

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        # this is a limit forced by VT service
        if self.limit > 300:
            self.limit = 300

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
                self.url + "/search", params=params, headers=self.headers
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
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
