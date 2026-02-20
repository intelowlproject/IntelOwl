# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification


class Stalkphish(classes.ObservableAnalyzer):
    url: str = "https://api.stalkphish.io/api/v1/"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        headers = {
            "User-Agent": "Stalkphish/IntelOwl",
            "Authorization": f"Token {self._api_key_name}",
        }
        obs_clsfn = self.observable_classification

        if obs_clsfn in [
            Classification.DOMAIN,
            Classification.URL,
            Classification.GENERIC,
        ]:
            uri = f"search/url/{self.observable_name}"
        elif obs_clsfn == Classification.IP:
            uri = f"search/ipv4/{self.observable_name}"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {obs_clsfn}. Supported are: ip, domain, url or generic."
            )

        try:
            response = requests.get(self.url + uri, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()
