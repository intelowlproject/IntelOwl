import logging
from typing import Dict

import requests
from requests import HTTPError

from api_app.analyzers_manager import classes
from api_app.choices import Classification
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

from .criminalip_base import CriminalIpBase

logger = logging.getLogger(__name__)


class CriminalIp(classes.ObservableAnalyzer, CriminalIpBase):
    malicious_info: bool = True  # IP
    privacy_threat: bool = False
    is_safe_dns_server: bool = False
    suspicious_info: bool = False
    banner_search: bool = True  # generic
    banner_stats: bool = False
    hash_view: bool = True  # domain

    def make_request(self, url: str, params: Dict[str, str] = None) -> Dict:
        resp = requests.get(url, headers=self.getHeaders(), params=params)
        resp.raise_for_status()
        resp = resp.json()
        if resp.get("status", None) not in  [None, 200]:
            raise HTTPError(resp.get("message", ""))
        logger.info(f"response from CriminalIp for {self.observable_name} -> {resp}")
        return resp

    def run(self):
        URLs = {
            Classification.IP.value: {
                "endpoints": {
                    "malicious_info": "/v1/feature/ip/malicious-info",
                    "privacy_threat": "/v1/feature/ip/privacy-threat",
                    "is_safe_dns_server": "/v1/feature/ip/is-safe-dns-server",
                    "suspicious_info": "/v2/feature/ip/suspicious-info",
                },
                "params": {"ip": self.observable_name},
            },
            Classification.DOMAIN.value: {
                "endpoints": {
                    "hash_view": "/v1/domain/quick/hash/view",
                },
                "params": {"domain": self.observable_name},
            },
            Classification.GENERIC.value: {
                "endpoints": {
                    "banner_search": "/v1/banner/search",
                    "banner_stats": "/v1/banner/stats",
                },
                "params": {"query": self.observable_name},
            },
        }

        if self.observable_classification not in URLs:
            return "invalid classification"

        resp = {}
        for key, endpoint in URLs[self.observable_classification]["endpoints"].items():
            if getattr(self, key):
                resp[key] = self.make_request(
                    f"{self.url}{endpoint}",
                    params=URLs[self.observable_classification]["params"],
                )

        return resp

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "data": {
                                "call_count": 0,
                                "domain": "example.com",
                                "reg_dtime": "2023-07-04 05:40:02",
                                "result": "safe",
                                "type": "trusted-domain",
                            },
                            "message": "api success",
                            "status": 200,
                        },
                        200,
                    ),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
