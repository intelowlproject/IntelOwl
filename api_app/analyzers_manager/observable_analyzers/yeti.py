# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class YETI(classes.ObservableAnalyzer):
    verify_ssl: bool
    results_count: int
    regex: False
    _url_key_name: str
    _api_key_name: str

    def run(self):
        # request payload
        payload = {
            "query": {"value": self._job.analyzable.name},
            "count": self.results_count,
        }

        # auth
        auth_url = f"{self._url_key_name}/api/v2/auth/api-token"
        auth_headers = {"x-yeti-apikey": self._api_key_name, "User-Agent": "IntelOwl"}

        try:
            auth_resp = requests.post(
                url=auth_url,
                headers=auth_headers,
                verify=self.verify_ssl,
                timeout=60,
            )
            auth_resp.raise_for_status()
            access_token = auth_resp.json().get("access_token")

            if not access_token:
                raise AnalyzerRunException("Failed to obtain access token from YETI.")
        except requests.RequestException as e:
            raise AnalyzerRunException(f"YETI Auth Request failed: {e}")

        headers = {"Accept": "application/json", "Authorization": f"Bearer {access_token}"}
        if self._url_key_name and self._url_key_name.endswith("/"):
            self._url_key_name = self._url_key_name[:-1]
        url = f"{self._url_key_name}/api/v2/observables/search"

        # search for observables
        resp = requests.post(
            url=url,
            headers=headers,
            json=payload,
            verify=self.verify_ssl,
        )
        resp.raise_for_status()

        return resp.json()
