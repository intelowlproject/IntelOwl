# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

mock_response = {
    {
        "query_status": "ok",
        "data": [
            {
                "id": "12",
                "ioc": "139.180.203.104:443",
                "threat_type": "botnet_cc",
                "threat_type_desc": "Indicator that identifies a botnet"
                " command&control server (C&C)",
                "ioc_type": "ip:port",
                "ioc_type_desc": "ip:port combination that is used for"
                " botnet Command&control (C&C)",
                "malware": "win.cobalt_strike",
                "malware_printable": "Cobalt Strike",
                "malware_alias": "Agentemis,BEACON,CobaltStrike",
                "malware_malpedia": "https:\/\/malpedia.caad.fkie.fraunhofer"
                ".de\/details\/win.cobalt_strike",
                "confidence_level": 75,
                "first_seen": "2020-12-06 09:10:23 UTC",
                "last_seen": None,
                "reference": None,
                "reporter": "abuse_ch",
                "tags": None,
                "malware_samples": [
                    {
                        "time_stamp": "2021-03-23 08:18:06 UTC",
                        "md5_hash": "5b7e82e051ade4b14d163eea2a17bf8b",
                        "sha256_hash": "b325c92fa540edeb89b95dbfd4400c1"
                        "cb33599c66859a87aead820e568a2ebe7",
                        "malware_bazaar": "https:\/\/bazaar.abuse.ch\/samp"
                        "le\/b325c92fa540edeb89b95dbfd440"
                        "0c1cb33599c66859a87aead820e568a"
                        "2ebe7\/",
                    }
                ],
            }
        ],
    }
}


class ThreatFox(classes.ObservableAnalyzer):
    url: str = "https://threatfox-api.abuse.ch/api/v1/"
    disable: bool = False  # optional

    def update(self) -> bool:
        pass

    def run(self):
        if self.disable:
            return {"disabled": True}

        payload = {"query": "search_ioc", "search_term": self.observable_name}

        response = requests.post(self.url, data=json.dumps(payload))
        response.raise_for_status()

        result = response.json()
        data = result.get("data", [])
        if data and isinstance(data, list):
            for index, element in enumerate(data):
                ioc_id = element.get("id", "")
                if ioc_id:
                    result["data"][index][
                        "link"
                    ] = f"https://threatfox.abuse.ch/ioc/{ioc_id}"
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse(
                        mock_response,
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
