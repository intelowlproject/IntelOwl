# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class AbuseIPDB(ObservableAnalyzer):
    url: str = "https://api.abuseipdb.com/api/v2/check"

    _api_key_name: str
    max_age: int
    max_reports: int
    verbose: bool

    def run(self):
        headers = {"Key": self._api_key_name, "Accept": "application/json"}
        params_ = {
            "ipAddress": self.observable_name,
            "maxAgeInDays": self.max_age,
            "verbose": self.verbose,
        }
        response = requests.get(self.url, params=params_, headers=headers)
        response.raise_for_status()

        result = response.json()
        reports = result.get("data", {}).get("reports", [])
        mapping = self._get_mapping()
        categories_found = {}
        # I want to use all the reports to extract the categories numbers
        # Afterwards we can prune them if they are too much
        for report in reports:
            report["categories_human_readable"] = []
            for category in report.get("categories", []):
                category_human_readable = mapping.get(category, "unknown category")
                report["categories_human_readable"].append(category_human_readable)
                if category_human_readable not in categories_found:
                    categories_found[category_human_readable] = 1
                else:
                    categories_found[category_human_readable] += 1

        # adding items to the base result
        result["categories_found"] = categories_found
        result["permalink"] = f"https://www.abuseipdb.com/check/{self.observable_name}"

        # limiting output result cause it can be really big
        if reports:
            result["data"]["reports"] = result["data"]["reports"][: self.max_reports]

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

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {"data": {"reports": [{"categories": [1, 2]}]}}, 200
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
