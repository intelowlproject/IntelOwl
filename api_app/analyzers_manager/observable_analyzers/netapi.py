# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from api_app.data_model_manager.enums import DataModelEvaluations

logger = logging.getLogger(__name__)

# Reliability of the MALICIOUS evaluation, see data_model_manager/classify.py:
# 6 and above shows as "malicious", below 6 as "suspicious".
# Listed now for the observable itself: an IP that attacked the NetAPI sensors
# within the last 48 hours, or a domain seen in the merged blocklists within the
# last 24 hours.
_RELIABILITY_LISTED_NOW = 7
# Listed now, but the match is a parent domain of the observable: the answer is
# about the parent, the host itself was not listed.
_RELIABILITY_PARENT_LISTED_NOW = 5
# Listed in the past only: most such entries are past incidents.
_RELIABILITY_LISTED_BEFORE = 3


class NetAPI(ObservableAnalyzer):
    """Check a domain or an IP address against the NetAPI compromised feed.

    One free request, no account and no API key (limits per client IP: 30
    requests a minute, 1,000 a day). IPs are answered from NetAPI's own honeypot
    feed (addresses that attacked its sensors, listed now = within 48 hours),
    domains from merged public blocklists (listed now = within 24 hours). For a
    host with subdomains the service also tries its parent domains and names the
    entry that matched in `matched_value`.
    """

    url: str = "https://netapi.com/api-json/"

    @classmethod
    def update(cls) -> bool:
        pass

    def __value(self) -> str:
        if self.observable_classification == Classification.URL:
            host = urlparse(self.observable_name).hostname
            if not host:
                raise AnalyzerRunException(f"could not extract a host from URL {self.observable_name}")
            return host
        return self.observable_name

    def run(self):
        params = {"method": "compromised-check", "value": self.__value()}
        try:
            response = requests.get(
                self.url,
                params=params,
                headers={"User-Agent": "IntelOwl"},
                timeout=30,
            )
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        try:
            result = response.json()
        except ValueError:
            result = None

        if response.status_code != 200 or not isinstance(result, dict):
            error = (result or {}).get("error") if isinstance(result, dict) else None
            message = error.get("message") if isinstance(error, dict) else response.text[:200]
            raise AnalyzerRunException(f"NetAPI answered HTTP {response.status_code}: {message}")

        return result

    def _do_create_data_model(self) -> bool:
        # Only a listing is an opinion. "Not listed" is not a statement that the
        # observable is safe, so it creates no data model. A past listing of a parent
        # domain says nothing about this host either, so it stays in the raw report only.
        report = self.report.report
        if report.get("listed_ever") is not True:
            return False
        if report.get("listed_now") is not True and not self.__same_site(report):
            return False
        return super()._do_create_data_model()

    @staticmethod
    def __same_site(report: dict) -> bool:
        """True when the feed entry is the observable itself, not a parent domain.

        `value` and `matched_value` are both normalized by the service (lower case,
        no trailing dot, punycode). The feed stores domains without a leading
        "www.", so "www.<domain>" matched on "<domain>" is the same site.
        """
        value, matched = report.get("value"), report.get("matched_value")
        return matched is not None and (matched == value or value == f"www.{matched}")

    def _update_data_model(self, data_model) -> None:
        super()._update_data_model(data_model)
        report = self.report.report

        data_model.evaluation = DataModelEvaluations.MALICIOUS.value
        if report.get("listed_now") is not True:
            data_model.reliability = _RELIABILITY_LISTED_BEFORE
        elif self.__same_site(report):
            data_model.reliability = _RELIABILITY_LISTED_NOW
        else:
            data_model.reliability = _RELIABILITY_PARENT_LISTED_NOW

        data_model.additional_info = {
            "listed_now": report.get("listed_now"),
            "matched_value": report.get("matched_value"),
            "first_seen": report.get("first_seen"),
            "last_seen": report.get("last_seen"),
            "block_reason": report.get("block_reason"),
        }
