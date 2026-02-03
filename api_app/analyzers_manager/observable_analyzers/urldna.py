# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class UrlDNA(ObservableAnalyzer):
    url: str = "https://api.urldna.io"

    urldna_analysis: str
    _api_key_name: str

    # Scan options
    device = "DESKTOP"
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0;Win64;x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36"
    )
    viewport_width = 1920
    viewport_height = 1080
    waiting_time = 5
    private_scan = False
    scanned_from = "DEFAULT"

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "IntelOwl",
            "Authorization": self._api_key_name,
        }

        self.session = requests.Session()
        self.session.headers = headers
        if self.urldna_analysis == "SEARCH":
            result = self.__urldna_search()
        elif self.urldna_analysis == "NEW_SCAN":
            scan_id = self.__urldna_new_scan()
            result = self.__poll_for_result(scan_id)
        else:
            raise AnalyzerRunException(
                f"Not supported analysis_type {self.urldna_analysis}. Supported are 'SEARCH' and 'NEW_SCAN'."
            )
        return result

    def __urldna_new_scan(self) -> str:
        submitted_url = self.observable_name
        data = {
            "submitted_url": submitted_url,
            "device": self.device,
            "user_agent": self.user_agent,
            "width": self.viewport_width,
            "height": self.viewport_height,
            "scanned_from": self.scanned_from,
            "waiting_time": self.waiting_time,
            "private_scan": self.private_scan,
        }
        uri = "/scan"
        response = self.session.post(self.url + uri, json=data)
        if response.status_code == 500:
            error_description = response.content
            raise requests.HTTPError(error_description)
        response.raise_for_status()
        return response.json().get("id", "")

    def __poll_for_result(self, scan_id):
        uri = f"/scan/{scan_id}"
        max_tries = 10
        poll_distance = 2
        result = {}
        time.sleep(10)
        for chance in range(max_tries):
            if chance:
                time.sleep(poll_distance)
            resp = self.session.get(self.url + uri)
            if resp.json().get("scan", {}).get("status") in ["RUNNING", "PENDING"]:
                continue
            result = resp.json()
            break
        return result

    def __urldna_search(self):
        uri = "/search"
        data = {"query": f"{self.observable_name}"}
        if self.observable_classification == Classification.URL:
            data["query"] = f"submitted_url = {self.observable_name}"
        elif self.observable_classification == Classification.DOMAIN:
            data["query"] = f"domain = {self.observable_name}"
        elif self.observable_classification == Classification.IP:
            data["query"] = f"ip = {self.observable_name}"
        else:
            data["query"] = f"{self.observable_name}"
        resp = self.session.post(self.url + uri, json=data)
        resp.raise_for_status()
        result = resp.json()
        return result
