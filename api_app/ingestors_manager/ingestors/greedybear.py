import logging
from typing import Any, Iterable
from unittest.mock import patch

import requests

from api_app.ingestors_manager.classes import Ingestor
from api_app.ingestors_manager.exceptions import IngestorRunException
from tests.mock_utils import MockUpResponse, if_mock_connections

logger = logging.getLogger(__name__)


class GreedyBear(Ingestor):
    # API endpoint
    url = "https://greedybear.honeynet.org/api/feeds/all/all/recent.json"
    # Days to check. From 1 to 7
    days: int
    # max iocs
    limit: int

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self) -> Iterable[Any]:
        result = requests.get(self.url)
        result.raise_for_status()
        content = result.json()
        if not isinstance(content["iocs"], list):
            raise IngestorRunException(f"Content {content} not expected")
        limit = min(len(content["iocs"]), self.limit)
        for elem in content["iocs"][:limit]:
            yield elem["value"].encode()

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
                                    "value": "fe80:0000:0000:0000:fc98:c3ff:feb6:b148",
                                    "scanner": True,
                                    "payload_request": False,
                                    "first_seen": "2024-05-29",
                                    "last_seen": "2025-02-01",
                                    "times_seen": 6437,
                                },
                                {
                                    "feed_type": "suricata",
                                    "value": "fe80:0000:0000:0000:fc67:4fff:fe6e:07b4",
                                    "scanner": True,
                                    "payload_request": False,
                                    "first_seen": "2024-05-29",
                                    "last_seen": "2025-02-01",
                                    "times_seen": 6633,
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
