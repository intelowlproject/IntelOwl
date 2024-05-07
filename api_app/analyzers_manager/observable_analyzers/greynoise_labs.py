# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import os

import requests
from django.conf import settings

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.models import PluginConfig
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)

url = "https://api.labs.greynoise.io/1/query"
db_name = "topc2s_ips.txt"
db_location = f"{settings.MEDIA_ROOT}/{db_name}"

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
        c2_domains payload hits pervasiveness } } } ",
        "ip_required": False,
        "db_location": db_location,
    },
}


class GreynoiseLabs(ObservableAnalyzer):
    _auth_token: str

    def run(self):
        result = {}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._auth_token}",
        }

        for key, value in queries.items():
            if not value["ip_required"]:
                if not os.path.isfile(value["db_location"]) and not self.update():
                    error_message = f"Failed extraction from {key} db"
                    self.report.errors.append(error_message)
                    self.report.save()
                    logger.error(error_message)
                    continue

                with open(value["db_location"], "r", encoding="utf-8") as f:
                    db = f.read()

                db_list = db.split("\n")
                if self.observable_name in db_list:
                    result[key] = {"found": True}
                else:
                    result[key] = {"found": False}
                continue

            json_body = {
                "query": value["query_string"],
                "variables": {"ip": f"{self.observable_name}"},
            }
            response = requests.post(headers=headers, json=json_body, url=url)
            response.raise_for_status()
            result[key] = response.json()

        return result

    @classmethod
    def _get_auth_token(cls):
        for plugin in PluginConfig.objects.filter(
            parameter__python_module=cls.python_module,
            parameter__is_secret=True,
            parameter__name="auth_token",
        ):
            if plugin.value:
                return plugin.value
        return None

    @classmethod
    def _update_db(cls, auth_token: str):
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {auth_token}",
        }

        try:
            logger.info("Fetching data from greynoise API (Greynoise_Labs).....")
            response = requests.post(
                headers=headers,
                json={"query": queries["topc2s"]["query_string"]},
                url=url,
            )
            response.raise_for_status()
            topc2s_data = response.json()

            with open(db_location, "w", encoding="utf-8") as f:
                for value in topc2s_data["data"]["topC2s"]["c2s"]:
                    ip = value["source_ip"]
                    if ip:
                        f.write(f"{ip}\n")

            if not os.path.exists(db_location):
                return False

            logger.info("Data fetched from greynoise API (Greynoise_Labs).....")
            return True
        except Exception as e:
            logger.exception(e)

    @classmethod
    def update(cls):
        auth_token = cls._get_auth_token()
        if auth_token:
            return cls._update_db(auth_token=auth_token)
        return False

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    side_effect=[
                        MockUpResponse(
                            {
                                "data": {
                                    "noiseRank": {
                                        "queryInfo": {
                                            "resultsAvailable": 1,
                                            "resultsLimit": 1,
                                        },
                                        "ips": [
                                            {
                                                "ip": "20.235.249.22",
                                                "noise_score": 12,
                                                "sensor_pervasiveness": "very low",
                                                "country_pervasiveness": "low",
                                                "payload_diversity": "very low",
                                                "port_diversity": "very low",
                                                "request_rate": "low",
                                            }
                                        ],
                                    }
                                }
                            },
                            200,
                        ),
                        MockUpResponse(
                            {
                                "data": {
                                    "topKnocks": {
                                        "queryInfo": {
                                            "resultsAvailable": 1,
                                            "resultsLimit": 1,
                                        },
                                    }
                                }
                            },
                            200,
                        ),
                        MockUpResponse(
                            {
                                "data": {
                                    "topC2s": {
                                        "queryInfo": {
                                            "resultsAvailable": 1914,
                                            "resultsLimit": 191,
                                        },
                                        "c2s": [
                                            {
                                                "source_ip": "91.92.247.12",
                                                "c2_ips": ["103.245.236.120"],
                                                "c2_domains": [],
                                                "hits": 11608,
                                            },
                                            {
                                                "source_ip": "14.225.208.190",
                                                "c2_ips": ["14.225.213.142"],
                                                "c2_domains": [],
                                                "hits": 2091,
                                                "pervasiveness": 26,
                                            },
                                            {
                                                "source_ip": "157.10.53.101",
                                                "c2_ips": ["14.225.208.190"],
                                                "c2_domains": [],
                                                "hits": 1193,
                                                "pervasiveness": 23,
                                            },
                                        ],
                                    },
                                },
                            },
                            200,
                        ),
                    ],
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
