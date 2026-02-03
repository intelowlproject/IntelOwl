import ipaddress
import logging
from typing import Any, Iterable
from unittest.mock import patch

import requests

from api_app.ingestors_manager.classes import Ingestor
from api_app.ingestors_manager.exceptions import (
    IngestorConfigurationException,
    IngestorRunException,
)
from tests.mock_utils import MockUpResponse, if_mock_connections

logger = logging.getLogger(__name__)


class GreedyBear(Ingestor):
    url: str
    feed_type: str
    attack_type: str
    age: str

    VALID_FEED_TYPES = {"log4j", "cowrie", "all"}
    VALID_ATTACK_TYPES = {"scanner", "payload_request", "all"}
    VALID_AGE = {"recent", "persistent", "likely_to_recur", "most_expected_hits"}

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self) -> Iterable[Any]:
        if self.feed_type not in self.VALID_FEED_TYPES:
            raise IngestorConfigurationException(
                f"Invalid feed_type: {self.feed_type}. Must be one of {self.VALID_FEED_TYPES}"
            )
        if self.attack_type not in self.VALID_ATTACK_TYPES:
            raise IngestorConfigurationException(
                f"Invalid attack_type: {self.attack_type}. Must be one of {self.VALID_ATTACK_TYPES}"
            )
        if self.age not in self.VALID_AGE:
            raise IngestorConfigurationException(f"Invalid age: {self.age}. Must be one of {self.VALID_AGE}")

        req_url = f"{self.url}/api/feeds/{self.feed_type}/{self.attack_type}/{self.age}.json"
        result = requests.get(req_url)
        result.raise_for_status()
        content = result.json()
        if not isinstance(content.get("iocs"), list):
            raise IngestorRunException(f"Content {content} not expected")

        limit = min(len(content["iocs"]), self.limit)
        for elem in content["iocs"][:limit]:
            value = elem.get("value")
            try:
                ipaddress.ip_address(value)
                yield value
            except ValueError:
                pass

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "license": "https://github.com/honeynet/GreedyBear/blob/main/FEEDS_LICENSE.md",
                            "iocs": [
                                {
                                    "feed_type": "suricata",
                                    "value": "91.205.219.185",
                                    "scanner": True,
                                    "payload_request": False,
                                    "first_seen": "2024-05-29",
                                    "last_seen": "2025-02-01",
                                    "times_seen": 6437,
                                },
                                {
                                    "feed_type": "suricata",
                                    "value": "88.210.32.15",
                                    "scanner": True,
                                    "payload_request": False,
                                    "first_seen": "2024-07-30",
                                    "last_seen": "2025-02-01",
                                    "times_seen": 61,
                                },
                            ],
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
