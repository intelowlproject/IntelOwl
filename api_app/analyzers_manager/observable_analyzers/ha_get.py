# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class HybridAnalysisGet(ObservableAnalyzer):
    url: str = "https://www.hybrid-analysis.com"
    api_url: str = f"{url}/api/v2/"
    sample_url: str = f"{url}/sample"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        headers = {
            "api-key": self._api_key_name,
            "user-agent": "Falcon Sandbox",
            "accept": "application/json",
        }
        obs_clsfn = self.observable_classification

        if obs_clsfn == Classification.DOMAIN:
            data = {"domain": self.observable_name}
            uri = "search/terms"
        elif obs_clsfn == Classification.IP:
            data = {"host": self.observable_name}
            uri = "search/terms"
        elif obs_clsfn == Classification.URL:
            data = {"url": self.observable_name}
            uri = "search/terms"
        elif obs_clsfn == Classification.HASH:
            data = {"hash": self.observable_name}
            uri = "search/hash"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {obs_clsfn}. "
                "Supported are: hash, ip, domain and url"
            )

        response = requests.post(self.api_url + uri, data=data, headers=headers)
        response.raise_for_status()

        result = response.json()
        # adding permalink to results
        if isinstance(result, list):
            for job in result:
                sha256 = job.get("sha256", "")
                job_id = job.get("job_id", "")
                if sha256:
                    job["permalink"] = f"{self.sample_url}/{sha256}"
                    if job_id:
                        job["permalink"] += f"/{job_id}"

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse(
                        [
                            {
                                "job_id": "1",
                                "sha256": "abcdefgh",
                            }
                        ],
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
