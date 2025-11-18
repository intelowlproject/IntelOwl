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
        # Prefer explicit config in analyzer instance (this class is used inside IntelOwl)
        cfg = getattr(self, "config", {}) or {}
        # old name might be 'key' or 'api_key' depending on install/migration
        self._api_key = cfg.get("api_key") or cfg.get("key") or self._api_key
        # decide whether to use v2
        api_version = cfg.get("api_version")
        if api_version:
            self._api_use_v2 = str(api_version).lower() == "v2"
        else:
            # allow an explicit boolean
            self._api_use_v2 = bool(cfg.get("use_v2", self._api_use_v2))

    def _build_v1_url(self, path, parameter):
        # v1 keeps old format: https://endpoint.apivoid.com/<path>/v1/pay-as-you-go/?key=APIKEY&<param>=value
        return f"{self.url_v1}/{path}/v1/pay-as-you-go/?key={self._api_key}&{parameter}={self.observable_name}"

    def _call_v1(self, path, parameter):
        complete_url = self._build_v1_url(path, parameter)
        r = requests.get(complete_url)
        r.raise_for_status()
        return r.json()

    def _call_v2(self, endpoint_path, payload):
        """
        Per APIVoid v2 docs, endpoints are under `https://api.apivoid.com/v2/<service>`
        and expect JSON POST with an API key supplied via header (e.g. X-API-Key).
        See APIVoid docs for exact endpoint names and payload shapes. Example endpoints:
          - /v2/ip-reputation
          - /v2/url-reputation
          - /v2/domain-reputation
        We send a JSON body and the X-API-Key header.
        """
        url = f"{self.url_v2}/{endpoint_path}"
        headers = {
            "Content-Type": "application/json",
            # APIVoid code examples and docs suggest X-API-Key header for v2 keys.
            "X-API-Key": self._api_key,
        }
        # Use POST to allow larger payloads and richer parameters (per docs/examples).
        r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
        r.raise_for_status()
        # APIVoid returns JSON objects; return parsed JSON here.
        return r.json()

    def run(self):
        """
        Determine observable type and call v2 if configured otherwise v1.
        """
        # Determine mapping for observable type
        if self.observable_classification == Classification.DOMAIN.value:
            # v1 path: domainbl, parameter host
            v1_path = "domainbl"
            v1_parameter = "host"
            # v2 endpoint: domain-reputation (docs use 'domain-reputation' or similar)
            v2_endpoint = "v2/domain-reputation"
            v2_payload = {"domain": self.observable_name}
        elif self.observable_classification == Classification.IP.value:
            v1_path = "iprep"
            v1_parameter = "ip"
            v2_endpoint = "v2/ip-reputation"
            v2_payload = {"ip": self.observable_name}
        elif self.observable_classification == Classification.URL.value:
            v1_path = "urlrep"
            v1_parameter = "url"
            v2_endpoint = "v2/url-reputation"
            v2_payload = {"url": self.observable_name}
        else:
            raise AnalyzerConfigurationException("not supported")

        # prefer v2 when configured
        if self._api_use_v2:
            try:
                return self._call_v2(v2_endpoint, v2_payload)
            except Exception:
                # For resilience, if v2 fails and a legacy key is present, try v1 fallback
                if self._api_key:
                    return self._call_v1(v1_path, v1_parameter)
                raise

        # default: v1 behaviour (existing)
        return self._call_v1(v1_path, v1_parameter)

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
                                            },
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
