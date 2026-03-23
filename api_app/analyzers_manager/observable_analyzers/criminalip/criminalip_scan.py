import logging
import time

import requests
from requests import HTTPError

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException

from .criminalip_base import CriminalIpBase

logger = logging.getLogger(__name__)


class CriminalIpScan(classes.ObservableAnalyzer, CriminalIpBase):
    status_endpoint = "/v1/domain/status/"
    scan_endpoint = "/v1/domain/scan/"
    private_scan_endpoint = "/v1/domain/scan/private"
    report_endpoint = "/v1/domain/report/"
    timeout: int = 20

    def update(self):
        pass

    def run(self):
        HEADER = self.getHeaders()
        poll_distance = 5  # seconds
        resp = requests.post(
            url=f"{self.url}{self.scan_endpoint}",
            headers=HEADER,
            data={"query": self.observable_name},
        )
        resp.raise_for_status()
        resp = resp.json()
        if resp.get("status", None) not in [None, 200]:
            raise HTTPError(resp.get("message", ""))
        logger.info(f"response from CriminalIp_scan for {self.observable_name} -> {resp}")

        logger.debug(f"{resp=}")
        scan_id = resp["data"]["scan_id"]
        while True:
            resp = requests.get(url=f"{self.url}{self.status_endpoint}{scan_id}", headers=HEADER)
            resp.raise_for_status()

            scan_percent = resp.json()["data"]["scan_percentage"]
            if scan_percent == 100:
                break
            time.sleep(poll_distance)
            self.timeout -= poll_distance
            if self.timeout <= 0:
                raise AnalyzerRunException(f"Timeout with scan percentage: {scan_percent}")
        resp = requests.get(url=f"{self.url}{self.report_endpoint}{scan_id}", headers=HEADER)
        resp.raise_for_status()
        resp = resp.json()
        logger.info(f"response from CriminalIp_scan for {self.observable_name} -> {resp}")
        return resp
