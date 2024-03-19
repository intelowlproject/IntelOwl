# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

queries = {
    "noiserank": {
        "query_string": "query NoiseRank($ip: String) { noiseRank(ip: $ip) \
            { queryInfo { resultsAvailable resultsLimit } ips { ip noise_score \
                sensor_pervasiveness country_pervasiveness payload_diversity \
                    port_diversity request_rate } } }",
        "ip_required": True,
    },
    "topknocks": {
        "query_string": "query TopKnocks($ip: String) { topKnocks(ip: $ip) \
            { queryInfo { resultsAvailable resultsLimit } knock { last_crawled \
            last_seen source_ip knock_port title favicon_mmh3_32 \
            favicon_mmh3_128 jarm ips emails links tor_exit headers apps } } } ",
        "ip_required": True,
    },
    "topc2s": {
        "query_string": "query TopC2s { topC2s { queryInfo \
        { resultsAvailable resultsLimit } c2s { source_ip c2_ips \
        c2_domains payload hits pervasiveness } } } "
    },
}


class GreynoiseLabs(ObservableAnalyzer):
    _auth_token: str

    def run(self):
        result = {}
        url = "https://api.labs.greynoise.io/1/query"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._auth_token}",
        }

        try:
            for key, value in queries.items():
                json_body = {"query": value["query_string"]}
                if "ip_required" in value and value["ip_required"]:
                    json_body["variables"] = {"ip": f"{self.observable_name}"}

                response = requests.post(headers=headers, json=json_body, url=url)
                response.raise_for_status()
                result[key] = response.json()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch("requests.post", return_value=MockUpResponse({}, 200))
            )
        ]
        return super()._monkeypatch(patches=patches)
