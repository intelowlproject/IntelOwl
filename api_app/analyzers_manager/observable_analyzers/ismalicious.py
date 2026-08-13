# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
"""isMalicious observable analyzer for IntelOwl.

Copy this file to:
  api_app/analyzers_manager/observable_analyzers/ismalicious.py
"""

from __future__ import annotations

from typing import Any

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

DEFAULT_API_URL = "https://api.ismalicious.com"


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

    try:
        response = requests.get(
            f"{api_url.rstrip('/')}/check",
            params={"query": query.strip(), "enrichment": "standard"},
            headers={"X-API-KEY": api_key, "Accept": "application/json"},
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise AnalyzerRunException(exc) from exc
    return response.json()


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
