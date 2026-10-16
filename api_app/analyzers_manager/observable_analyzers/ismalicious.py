# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
"""isMalicious observable analyzer: GET /check for IPs, domains and URLs."""

from __future__ import annotations

from typing import Any

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

DEFAULT_API_URL = "https://api.ismalicious.com"
# Identifies the analyzer to the isMalicious API, which attributes usage by
# User-Agent prefix.
USER_AGENT = "ismalicious-intelowl/1.0.1 (+https://ismalicious.com)"


def refusal_message(response: requests.Response) -> str:
    """Preserve the API's quota or rate-limit explanation and next step."""
    try:
        body = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        message = body.get("message") or body.get("error")
        if isinstance(message, str) and message:
            cta = body.get("cta")
            url = cta.get("url") if isinstance(cta, dict) else None
            if isinstance(url, str) and url and url not in message:
                return f"{message} {url}"
            return message
    return "Rate limit exceeded"


def check_indicator(
    query: str,
    api_key: str,
    api_url: str = DEFAULT_API_URL,
    timeout: int = 30,
) -> dict[str, Any]:
    """GET /check?query=…&enrichment=standard with X-API-KEY."""
    if not query or not query.strip():
        raise ValueError("query is required")
    if not api_key:
        raise ValueError("api_key is required")
    if not isinstance(api_url, str) or api_url.rstrip("/") != DEFAULT_API_URL:
        raise AnalyzerRunException("isMalicious requests must target https://api.ismalicious.com")

    try:
        response = requests.get(
            f"{api_url.rstrip('/')}/check",
            params={"query": query.strip(), "enrichment": "standard"},
            headers={
                "X-API-KEY": api_key,
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            timeout=timeout,
            allow_redirects=False,
        )
        if response.status_code == 429:
            raise AnalyzerRunException(refusal_message(response))
        response.raise_for_status()
        if 300 <= response.status_code < 400:
            raise AnalyzerRunException("isMalicious returned a redirect; credentials were not forwarded")
        report = response.json()
    except requests.RequestException as exc:
        raise AnalyzerRunException(exc) from exc
    if not isinstance(report, dict) or not report:
        raise AnalyzerRunException(
            "isMalicious returned an invalid response: expected a non-empty JSON object"
        )
    return report


class IsMalicious(ObservableAnalyzer):
    url: str = DEFAULT_API_URL
    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        return True

    def run(self) -> dict[str, Any]:
        return check_indicator(
            query=self.observable_name,
            api_key=self._api_key_name,
            api_url=self.url,
        )

    def _update_data_model(self, data_model) -> None:
        """Keep provider evidence without deriving an IntelOwl trust evaluation.

        isMalicious risk and confidence are separate scores. Neither supplies
        an IntelOwl reliability value, and a non-hit does not establish trust.
        The complete response remains available in the analyzer report.
        """
        super()._update_data_model(data_model)
        report = self.report.report
        data_model.additional_info = {
            key: report[key]
            for key in (
                "enrichmentLevel",
                "malicious",
                "lookupStatus",
                "confidence",
                "riskScore",
                "classification",
                "sources",
                "reputation",
                "contradictions",
            )
            if key in report
        }
