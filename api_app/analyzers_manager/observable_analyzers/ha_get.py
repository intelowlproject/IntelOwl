# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager import classes
from intel_owl import secrets


class HybridAnalysisGet(classes.ObservableAnalyzer):
    base_url: str = "https://www.hybrid-analysis.com"
    api_url: str = f"{base_url}/api/v2/"
    sample_url: str = f"{base_url}/sample"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "HA_KEY")

    def run(self):
        api_key = secrets.get_secret(self.api_key_name)
        if not api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name {self.api_key_name}"
            )

        headers = {
            "api-key": api_key,
            "user-agent": "Falcon Sandbox",
            "accept": "application/json",
        }
        obs_clsfn = self.observable_classification

        if obs_clsfn == "domain":
            data = {"domain": self.observable_name}
            uri = "search/terms"
        elif obs_clsfn == "ip":
            data = {"host": self.observable_name}
            uri = "search/terms"
        elif obs_clsfn == "url":
            data = {"url": self.observable_name}
            uri = "search/terms"
        elif obs_clsfn == "hash":
            data = {"hash": self.observable_name}
            uri = "search/hash"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {obs_clsfn}. "
                "Supported are: hash, ip, domain and url"
            )

        try:
            response = requests.post(self.api_url + uri, data=data, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

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
