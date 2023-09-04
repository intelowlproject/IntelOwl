# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class Koodous(classes.ObservableAnalyzer):
    base_url: str = "https://developer.koodous.com/apks/"
    query_analysis = "/analysis"

    _api_key_name: str

    def get_response(self, url):
        return requests.get(
            url, headers={"Authorization": f"Token {self._api_key_name}"}
        )

    def run(self):
        try:
            common_url = self.base_url + self.observable_name

            apk_info = self.get_response(common_url)
            apk_info.raise_for_status()

            apk_analysis = self.get_response(common_url + self.query_analysis)
            apk_analysis.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        response = {
            "apk_info": apk_info.json(),
            "analysis_report": apk_analysis.json(),
        }

        return response

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
