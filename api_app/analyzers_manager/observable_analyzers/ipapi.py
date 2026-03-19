# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Dict

from api_app import http_utils
from api_app.analyzers_manager import classes


class IPApi(classes.ObservableAnalyzer):
    batch_url = "http://ip-api.com/batch"
    dns_url = "http://edns.ip-api.com/json"

    fields: str
    lang: str

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.IP = [
            {
                "query": self.observable_name,
                "fields": self.fields,
                "lang": self.lang,
            }
        ]

    def run(self):
        response_batch = http_utils.post(self.batch_url, json=self.IP)
        response_batch.raise_for_status()

        response_dns = http_utils.get(self.dns_url)
        response_dns.raise_for_status()

        response = {"ip_info": response_batch.json(), "dns_info": response_dns.json()}

        return response
