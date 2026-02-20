import logging
from typing import Any, Iterable
from unittest.mock import patch

import requests

from api_app.ingestors_manager.classes import Ingestor
from api_app.ingestors_manager.exceptions import IngestorRunException
from api_app.mixins import AbuseCHMixin
from tests.mock_utils import MockUpResponse, if_mock_connections

logger = logging.getLogger(__name__)


class ThreatFox(AbuseCHMixin, Ingestor):
    # API endpoint
    url = "https://threatfox-api.abuse.ch/api/v1/"
    # Days to check. From 1 to 7
    days: int

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self) -> Iterable[Any]:
        result = requests.post(
            self.url,
            json={"query": "get_iocs", "days": self.days},
            headers=self.authentication_header,
        )
        result.raise_for_status()
        content = result.json()
        logger.info(f"ThreatFox data is {content}")
        if content["query_status"] != "ok":
            raise IngestorRunException(f"Query status is invalid: {content['query_status']}")
        if not isinstance(content["data"], list):
            raise IngestorRunException(f"Content {content} not expected")
        for elem in content["data"]:
            if elem["ioc_type"] == "ip:port":
                # we do not manage ip with the port at the moment
                yield elem["ioc"].split(":")[0]
            else:
                yield elem["ioc"]

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse(
                        {
                            "query_status": "ok",
                            "data": [
                                {
                                    "id": "41",
                                    "ioc": "gaga.com",
                                    "threat_type": "botnet_cc",
                                    "threat_type_desc": "Indicator that"
                                    " identifies a botnet"
                                    " command&control server (C&C)",
                                    "ioc_type": "domain",
                                    "ioc_type_desc": "Domain that is used for botnet Command&control (C&C)",
                                    "malware": "win.dridex",
                                    "malware_printable": "Dridex",
                                    "malware_alias": None,
                                    "malware_malpedia": r"https://malpedia.caad."
                                    "fkie.fraunhofer.de"
                                    r"/details/win.dridex",
                                    "confidence_level": 50,
                                    "first_seen": "2020-12-08 13:36:27 UTC",
                                    "last_seen": None,
                                    "reporter": "abuse_ch",
                                    "reference": r"https://twitter.com/JAMESWT_MHT"
                                    r"/status/1336229725082177536",
                                    "tags": ["exe", "test"],
                                }
                            ],
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
