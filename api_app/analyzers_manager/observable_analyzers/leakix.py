import logging

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class LeakIx(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for LeakIx API.
    """

    def update(self) -> bool:
        pass

    url: str = "https://leakix.net/host"
    _api_key: str = ""

    def run(self):
        headers = {"api-key": f"{self._api_key}", "Accept": "application/json"}
        response = requests.get(
            url=self.url + f"/{self.observable_name}", headers=headers
        )
        response.raise_for_status()
        return response.json()

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "Leaks": None,
                            "Services": [
                                {
                                    "ip": "78.47.222.185",
                                    "mac": "",
                                    "ssh": {
                                        "motd": "",
                                        "banner": "",
                                        "version": 0,
                                        "fingerprint": """SHA256:tIWzYmTZxEx3IDfaJu
                                        9FvMiE0xvhumiLkugD51yuLrs""",
                                    },
                                    "ssl": {
                                        "jarm": "",
                                        "enabled": False,
                                        "version": "",
                                        "detected": False,
                                        "certificate": {
                                            "cn": "",
                                            "valid": False,
                                            "domain": None,
                                            "key_algo": "",
                                            "key_size": 0,
                                            "not_after": "0001-01-01T00:00:00Z",
                                            "not_before": "0001-01-01T00:00:00Z",
                                            "fingerprint": "",
                                            "issuer_name": "",
                                        },
                                        "cypher_suite": "",
                                    },
                                    "host": "78.47.222.185",
                                    "http": {
                                        "url": "",
                                        "root": "",
                                        "title": "",
                                        "header": None,
                                        "length": 0,
                                        "status": 0,
                                        "favicon_hash": "",
                                    },
                                    "leak": {
                                        "type": "",
                                        "stage": "",
                                        "dataset": {
                                            "rows": 0,
                                            "size": 0,
                                            "files": 0,
                                            "infected": False,
                                            "collections": 0,
                                            "ransom_notes": None,
                                        },
                                        "severity": "",
                                    },
                                    "port": "22",
                                    "tags": ["rescan"],
                                    "time": "2024-07-09T22:55:48.772687919Z",
                                    "geoip": {
                                        "location": {"lat": 50.6584, "lon": 7.8268},
                                        "city_name": "Hachenburg",
                                        "region_name": "Rheinland-Pfalz",
                                        "country_name": "Germany",
                                        "continent_name": "Europe",
                                        "region_iso_code": "DE-RP",
                                        "country_iso_code": "DE",
                                    },
                                    "vendor": "",
                                    "network": {
                                        "asn": 24940,
                                        "network": "78.46.0.0/15",
                                        "organization_name": "Hetzner Online GmbH",
                                    },
                                    "reverse": "",
                                    "service": {
                                        "software": {
                                            "os": "",
                                            "name": "",
                                            "modules": None,
                                            "version": "",
                                            "fingerprint": "",
                                        },
                                        "credentials": {
                                            "key": "",
                                            "raw": None,
                                            "noauth": False,
                                            "password": "",
                                            "username": "",
                                        },
                                    },
                                    "summary": "",
                                    "protocol": "ssh",
                                    "transport": ["tcp"],
                                    "event_type": "service",
                                    "event_source": "SSHOpenPlugin",
                                    "event_pipeline": ["tcpid", "SSHOpenPlugin"],
                                    "event_fingerprint": """fe6a4680fe6a4680fe6a4680fe
                        6a4680fe6a4680fe6a4680fe6a4680fe6a4680""",
                                },
                                {
                                    "ip": "78.47.222.185",
                                    "mac": "",
                                    "ssh": {
                                        "motd": "",
                                        "banner": "",
                                        "version": 0,
                                        "fingerprint": """SHA256:tIWzYmTZxEx3IDfa
                            Ju9FvMiE0xvhumiLkugD51yuLrs""",
                                    },
                                    "ssl": {
                                        "jarm": "",
                                        "enabled": False,
                                        "version": "",
                                        "detected": False,
                                        "certificate": {
                                            "cn": "",
                                            "valid": False,
                                            "domain": None,
                                            "key_algo": "",
                                            "key_size": 0,
                                            "not_after": "0001-01-01T00:00:00Z",
                                            "not_before": "0001-01-01T00:00:00Z",
                                            "fingerprint": "",
                                            "issuer_name": "",
                                        },
                                        "cypher_suite": "",
                                    },
                                    "host": "78.47.222.185",
                                    "http": {
                                        "url": "",
                                        "root": "",
                                        "title": "",
                                        "header": None,
                                        "length": 0,
                                        "status": 0,
                                        "favicon_hash": "",
                                    },
                                    "leak": {
                                        "type": "",
                                        "stage": "",
                                        "dataset": {
                                            "rows": 0,
                                            "size": 0,
                                            "files": 0,
                                            "infected": False,
                                            "collections": 0,
                                            "ransom_notes": None,
                                        },
                                        "severity": "",
                                    },
                                    "port": "22",
                                    "tags": ["rescan"],
                                    "time": "2024-07-07T23:17:08.554427934Z",
                                    "geoip": {
                                        "location": {"lat": 50.6584, "lon": 7.8268},
                                        "city_name": "Hachenburg",
                                        "region_name": "Rheinland-Pfalz",
                                        "country_name": "Germany",
                                        "continent_name": "Europe",
                                        "region_iso_code": "DE-RP",
                                        "country_iso_code": "DE",
                                    },
                                    "vendor": "",
                                    "network": {
                                        "asn": 24940,
                                        "network": "78.46.0.0/15",
                                        "organization_name": "Hetzner Online GmbH",
                                    },
                                    "reverse": "",
                                    "service": {
                                        "software": {
                                            "os": "",
                                            "name": "",
                                            "modules": None,
                                            "version": "",
                                            "fingerprint": "",
                                        },
                                        "credentials": {
                                            "key": "",
                                            "raw": None,
                                            "noauth": False,
                                            "password": "",
                                            "username": "",
                                        },
                                    },
                                    "summary": "",
                                    "protocol": "ssh",
                                    "transport": ["tcp"],
                                    "event_type": "service",
                                    "event_source": "SSHOpenPlugin",
                                    "event_pipeline": ["tcpid", "SSHOpenPlugin"],
                                    "event_fingerprint": """fe6a4680fe6a4680fe6a4680fe6a
                                    4680fe6a4680fe6a4680fe6a4680fe6a4680""",
                                },
                                {
                                    "ip": "78.47.222.185",
                                    "mac": "",
                                    "ssh": {
                                        "motd": "",
                                        "banner": "",
                                        "version": 0,
                                        "fingerprint": """SHA256:tIWzYmTZxEx3IDfaJ
                                        u9FvMiE0xvhumiLkugD51yuLrs""",
                                    },
                                    "ssl": {
                                        "jarm": "",
                                        "enabled": False,
                                        "version": "",
                                        "detected": False,
                                        "certificate": {
                                            "cn": "",
                                            "valid": False,
                                            "domain": None,
                                            "key_algo": "",
                                            "key_size": 0,
                                            "not_after": "0001-01-01T00:00:00Z",
                                            "not_before": "0001-01-01T00:00:00Z",
                                            "fingerprint": "",
                                            "issuer_name": "",
                                        },
                                        "cypher_suite": "",
                                    },
                                    "host": "78.47.222.185",
                                    "http": {
                                        "url": "",
                                        "root": "",
                                        "title": "",
                                        "header": None,
                                        "length": 0,
                                        "status": 0,
                                        "favicon_hash": "",
                                    },
                                    "leak": {
                                        "type": "",
                                        "stage": "",
                                        "dataset": {
                                            "rows": 0,
                                            "size": 0,
                                            "files": 0,
                                            "infected": False,
                                            "collections": 0,
                                            "ransom_notes": None,
                                        },
                                        "severity": "",
                                    },
                                    "port": "22",
                                    "tags": ["rescan"],
                                    "time": "2024-07-05T22:25:11.350175468Z",
                                    "geoip": {
                                        "location": {"lat": 50.6584, "lon": 7.8268},
                                        "city_name": "Hachenburg",
                                        "region_name": "Rheinland-Pfalz",
                                        "country_name": "Germany",
                                        "continent_name": "Europe",
                                        "region_iso_code": "DE-RP",
                                        "country_iso_code": "DE",
                                    },
                                    "vendor": "",
                                    "network": {
                                        "asn": 24940,
                                        "network": "78.46.0.0/15",
                                        "organization_name": "Hetzner Online GmbH",
                                    },
                                    "reverse": "",
                                    "service": {
                                        "software": {
                                            "os": "",
                                            "name": "",
                                            "modules": None,
                                            "version": "",
                                            "fingerprint": "",
                                        },
                                        "credentials": {
                                            "key": "",
                                            "raw": None,
                                            "noauth": False,
                                            "password": "",
                                            "username": "",
                                        },
                                    },
                                    "summary": "",
                                    "protocol": "ssh",
                                    "transport": ["tcp"],
                                    "event_type": "service",
                                    "event_source": "SSHOpenPlugin",
                                    "event_pipeline": ["tcpid", "SSHOpenPlugin"],
                                    "event_fingerprint": """fe6a4680fe6a4680fe6a4680f
                                    e6a4680fe6a4680fe6a4680fe6a4680fe6a4680""",
                                },
                                {
                                    "ip": "78.47.222.185",
                                    "mac": "",
                                    "ssh": {
                                        "motd": "",
                                        "banner": "",
                                        "version": 0,
                                        "fingerprint": """SHA256:tIWzYmTZxEx3IDfaJu
                                        9FvMiE0xvhumiLkugD51yuLrs""",
                                    },
                                    "ssl": {
                                        "jarm": "",
                                        "enabled": False,
                                        "version": "",
                                        "detected": False,
                                        "certificate": {
                                            "cn": "",
                                            "valid": False,
                                            "domain": None,
                                            "key_algo": "",
                                            "key_size": 0,
                                            "not_after": "0001-01-01T00:00:00Z",
                                            "not_before": "0001-01-01T00:00:00Z",
                                            "fingerprint": "",
                                            "issuer_name": "",
                                        },
                                        "cypher_suite": "",
                                    },
                                    "host": "78.47.222.185",
                                    "http": {
                                        "url": "",
                                        "root": "",
                                        "title": "",
                                        "header": None,
                                        "length": 0,
                                        "status": 0,
                                        "favicon_hash": "",
                                    },
                                    "leak": {
                                        "type": "",
                                        "stage": "",
                                        "dataset": {
                                            "rows": 0,
                                            "size": 0,
                                            "files": 0,
                                            "infected": False,
                                            "collections": 0,
                                            "ransom_notes": None,
                                        },
                                        "severity": "",
                                    },
                                    "port": "22",
                                    "tags": [],
                                    "time": "2024-07-03T21:03:50.838009372Z",
                                    "geoip": {
                                        "location": {"lat": 50.6584, "lon": 7.8268},
                                        "city_name": "Hachenburg",
                                        "region_name": "Rheinland-Pfalz",
                                        "country_name": "Germany",
                                        "continent_name": "Europe",
                                        "region_iso_code": "DE-RP",
                                        "country_iso_code": "DE",
                                    },
                                    "vendor": "",
                                    "network": {
                                        "asn": 24940,
                                        "network": "78.46.0.0/15",
                                        "organization_name": "Hetzner Online GmbH",
                                    },
                                    "reverse": "",
                                    "service": {
                                        "software": {
                                            "os": "",
                                            "name": "",
                                            "modules": None,
                                            "version": "",
                                            "fingerprint": "",
                                        },
                                        "credentials": {
                                            "key": "",
                                            "raw": None,
                                            "noauth": False,
                                            "password": "",
                                            "username": "",
                                        },
                                    },
                                    "summary": "",
                                    "protocol": "ssh",
                                    "transport": ["tcp"],
                                    "event_type": "service",
                                    "event_source": "SSHOpenPlugin",
                                    "event_pipeline": [
                                        "l9filter",
                                        "tcpid",
                                        "SSHOpenPlugin",
                                    ],
                                    "event_fingerprint": """fe6a4680fe6a4680fe6a4680fe
                                    6a4680fe6a4680fe6a4680fe6a4680fe6a4680""",
                                },
                            ],
                        },
                        200,
                    ),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
