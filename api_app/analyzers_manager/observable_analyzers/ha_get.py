# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification


class HybridAnalysisGet(ObservableAnalyzer):
    url: str = "https://www.hybrid-analysis.com"
    api_url: str = f"{url}/api/v2/"
    sample_url: str = f"{url}/sample"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def _fetch_sample_summary(self, sha256: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        overview_uri = f"overview/{sha256}"
        try:
            res = requests.get(self.api_url + overview_uri, headers=headers)
            res.raise_for_status()
            data = res.json()
            return data if isinstance(data, dict) else None
        except requests.RequestException:
            return None

    def _search_terms(self, key: str, value: str, headers: Dict[str, str]):
        return requests.post(
            self.api_url + "search/terms",
            data={key: value},
            headers=headers,
        )

    def _search_hash(self, value: str, headers: Dict[str, str]):
        return requests.get(
            self.api_url + "search/hash",
            params={"hash": value},
            headers=headers,
        )

    def _add_permalink(self, obj: Dict[str, Any], sha: str, job_id: str = ""):
        link = f"{self.sample_url}/{sha}"
        if job_id:
            link += f"/{job_id}"
        obj["permalink"] = link

    def _process_full_item(self, item: Dict[str, Any]):
        sha = item.get("sha256", "")
        job_id = item.get("job_id", "")
        if sha:
            self._add_permalink(item, sha, job_id)
        return item

    def _process_minimal_item(self, item: Any, headers: Dict[str, str]):
        sha = item if isinstance(item, str) else item.get("sha256") or item.get("hash")
        if not sha:
            return {}

        summary = self._fetch_sample_summary(sha, headers)
        if summary:
            job_id = summary.get("job_id", "")
            self._add_permalink(summary, sha, job_id)
            return summary

        if isinstance(item, dict):
            self._add_permalink(item, sha)
            return item

        return {"sha256": sha, "permalink": f"{self.sample_url}/{sha}"}

    def _process_hash_results(self, result: List[Any], headers: Dict[str, str]):
        detailed = []
        for item in result:
            if isinstance(item, dict) and (
                item.get("job_id") or item.get("verdict") or item.get("threat_score")
            ):
                detailed.append(self._process_full_item(item))
            else:
                processed = self._process_minimal_item(item, headers)
                if processed:
                    detailed.append(processed)
        return detailed or result

    def _add_permalink_list(self, result: List[Dict[str, Any]]):
        for item in result:
            sha = item.get("sha256", "")
            job_id = item.get("job_id", "")
            if sha:
                self._add_permalink(item, sha, job_id)

    def run(self) -> Any:
        headers = {
            "api-key": self._api_key_name,
            "user-agent": "Falcon Sandbox",
            "accept": "application/json",
        }

        obs_cls = self.observable_classification
        value = self.observable_name

        if obs_cls == Classification.DOMAIN:
            response = self._search_terms("domain", value, headers)
        elif obs_cls == Classification.IP:
            response = self._search_terms("host", value, headers)
        elif obs_cls == Classification.URL:
            response = self._search_terms("url", value, headers)
        elif obs_cls == Classification.HASH:
            response = self._search_hash(value, headers)
        else:
            raise AnalyzerRunException(
                f"not supported observable type {obs_cls}. Supported are: hash, ip, domain and url"
            )

        response.raise_for_status()
        result = response.json()

        if obs_cls == Classification.HASH and isinstance(result, list):
            return self._process_hash_results(result, headers)

        if isinstance(result, list):
            self._add_permalink_list(result)

        return result
