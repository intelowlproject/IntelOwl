# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes


class Koodous(classes.ObservableAnalyzer):
    url: str = "https://developer.koodous.com/apks/"
    query_analysis = "/analysis"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def get_response(self, url):
        return requests.get(url, headers={"Authorization": f"Token {self._api_key_name}"})

    def run(self):
        common_url = self.url + self.observable_name

        apk_info = self.get_response(common_url)
        apk_info.raise_for_status()

        apk_analysis = self.get_response(common_url + self.query_analysis)
        apk_analysis.raise_for_status()

        response = {
            "apk_info": apk_info.json(),
            "analysis_report": apk_analysis.json(),
        }

        return response
