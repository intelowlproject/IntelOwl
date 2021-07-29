# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers.classes import ObservableAnalyzer
from intel_owl import secrets


class AbuseIPDB(ObservableAnalyzer):
    url: str = "https://api.abuseipdb.com/api/v2/check"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get(
            "api_key_name", "ABUSEIPDB_KEY"
        )
        self.__api_key = secrets.get_secret(self.api_key_name)

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )

        headers = {"Key": self.__api_key, "Accept": "application/json"}
        params = {
            "ipAddress": self.observable_name,
            "maxAgeInDays": 180,
            "verbose": True,
        }
        response = requests.get(self.url, params=params, headers=headers)
        response.raise_for_status()

        result = response.json()
        reports = result.get("data", {}).get("reports", {})
        mapping = self._get_mapping()
        for report in reports:
            report["categories_human_readable"] = []
            for category in report.get("categories", []):
                if category in mapping:
                    category_human_readable = mapping[category]
                else:
                    category_human_readable = "unknown category"
                report["categories_human_readable"].append(category_human_readable)

        result["permalink"] = f"https://www.abuseipdb.com/check/{self.observable_name}"

        return result

    @staticmethod
    def _get_mapping():
        mapping = {
            1: "DNS Compromise",
            2: "DNS Poisoning",
            3: "Fraud Orders",
            4: "DDOS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VOIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted",
        }
        return mapping
