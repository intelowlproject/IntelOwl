# flake8: noqa
# done for the mocked response,
# everything else is linted and tested
# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from api_app.choices import Classification

from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class ApiVoidAnalyzer(classes.ObservableAnalyzer):
    """
    APIVoid analyzer with support for both the legacy v1 endpoints (query param key)
    and the new v2 endpoints (header X-API-Key + JSON POST). The analyzer will use
    v2 when `self.config.get("api_version") == "v2"` or if `self._api_use_v2` is True.
    Otherwise it falls back to v1 behaviour for backwards compatibility.
    """

    # Legacy default (kept for backward compatibility)
    url_v1 = "https://endpoint.apivoid.com"
    # New base (v2) per APIVoid docs/changelog
    url_v2 = "https://api.apivoid.com"

    _api_key: str = None
    _api_use_v2: bool = False

    def update(self):
        """
        Pull API key and optional flags from analyzer configuration.
        Expected config keys:
          - api_key
          - api_version (optional) -> "v1" or "v2"
          - use_v2 (optional, bool) -> explicit boolean flag
        """
        cfg = getattr(self, "config", {}) or {}
        # Support legacy config naming
        self._api_key = cfg.get("api_key") or cfg.get("key") or self._api_key

        api_version = cfg.get("api_version")
        if api_version:
            self._api_use_v2 = str(api_version).lower() == "v2"
        else:
            self._api_use_v2 = bool(cfg.get("use_v2", self._api_use_v2))

    def _build_v1_url(self, path, parameter):
        return (
            f"{self.url_v1}/{path}/v1/pay-as-you-go/?key={self._api_key}"
            f"&{parameter}={self.observable_name}"
        )

    def _call_v1(self, path, parameter):
        url = self._build_v1_url(path, parameter)
        r = requests.get(url)
        r.raise_for_status()
        return r.json()

    def _call_v2(self, endpoint_path, payload):
        """
        APIVoid v2: JSON POST with `X-API-Key` header.
        """
        url = f"{self.url_v2}/{endpoint_path}"
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self._api_key,
        }
        r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
        r.raise_for_status()
        return r.json()

    def run(self):
        """
        Select endpoint based on observable classification,
        prefer v2 when configured, otherwise fallback to v1.
        """
        if self.observable_classification == Classification.DOMAIN.value:
            v1_path = "domainbl"
            v1_param = "host"
            v2_endpoint = "v2/domain-reputation"
            v2_payload = {"domain": self.observable_name}

        elif self.observable_classification == Classification.IP.value:
            v1_path = "iprep"
            v1_param = "ip"
            v2_endpoint = "v2/ip-reputation"
            v2_payload = {"ip": self.observable_name}

        elif self.observable_classification == Classification.URL.value:
            v1_path = "urlrep"
            v1_param = "url"
            v2_endpoint = "v2/url-reputation"
            v2_payload = {"url": self.observable_name}

        else:
            raise AnalyzerConfigurationException("not supported")

        if self._api_use_v2:
            try:
                return self._call_v2(v2_endpoint, v2_payload)
            except Exception:
                if self._api_key:
                    return self._call_v1(v1_path, v1_param)
                raise

        return self._call_v1(v1_path, v1_param)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "data": {
                                "report": {
                                    "ip": "2.57.122.0",
                                    "version": "v4",
                                    "blacklists": {
                                        "engines": {
                                            "0": {
                                                "engine": "0spam",
                                                "detected": False,
                                                "reference": "https://0spam.org/",
                                                "elapsed": "0.09",
                                            }
                                        },
                                        "detections": 7,
                                        "engines_count": 79,
                                        "detection_rate": "9%",
                                        "scantime": "1.35",
                                    },
                                    "information": {
                                        "reverse_dns": "",
                                        "continent_code": "EU",
                                        "continent_name": "Europe",
                                        "country_code": "RO",
                                        "country_name": "Romania",
                                        "country_currency": "RON",
                                        "country_calling_code": "40",
                                        "region_name": "Bucuresti",
                                        "city_name": "Bucharest",
                                        "latitude": 44.432301,
                                        "longitude": 26.10607,
                                        "isp": "Pptechnology Limited",
                                        "asn": "AS47890",
                                    },
                                    "anonymity": {
                                        "is_proxy": False,
                                        "is_webproxy": False,
                                        "is_vpn": False,
                                        "is_hosting": False,
                                        "is_tor": False,
                                    },
                                    "risk_score": {"result": 100},
                                }
                            },
                            "credits_remained": 24.76,
                            "estimated_queries": "309",
                            "elapsed_time": "2.58",
                            "success": True,
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
