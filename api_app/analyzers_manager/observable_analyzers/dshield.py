# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class DShield(ObservableAnalyzer):
    url: str = "https://isc.sans.edu/api"

    def update(self) -> bool:
        pass

    def run(self):
        headers = {"User-Agent": "IntelOwl"}

        result = {
            "ip_info": {"uri": f"/ip/{self.observable_name}?json"},
            "ip_details": {"uri": f"/ipdetails/{self.observable_name}?json"},
        }

        for query_type, values in result.items():
            try:
                response = requests.get(self.url + values["uri"], headers=headers)
                response.raise_for_status()
            except requests.RequestException as e:
                logger.warning(e, stack_info=True)
                self.report.errors.append(
                    f"{query_type} check failed for {self.observable_name}. Err {e}"
                )
                self.report.save()
            else:
                result[query_type] = response.json()

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
