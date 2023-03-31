# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class Pulsedive(ObservableAnalyzer):
    base_url: str = "https://pulsedive.com/api"
    max_tries: int = 10
    poll_distance: int = 10

    scan_mode: str
    _api_key_name: str

    def config(self):
        super().config()
        supported_scan_values = ["basic", "passive", "active"]
        if self.scan_mode not in supported_scan_values:
            raise AnalyzerConfigurationException(
                "scan_mode is not a supported value."
                f" Supported are {supported_scan_values}"
            )
        self.probe = 1 if self.scan_mode == "active" else 0  # else is "passive"

    def run(self):
        result = {}
        self.default_param = ""
        # optional API key
        if not hasattr(self, "_api_key_name"):
            warning = "No API key retrieved"
            logger.info(
                f"{warning}. Continuing without API key..." f" <- {self.__repr__()}"
            )
            self.report.errors.append(warning)
        else:
            self.default_param = f"&key={self._api_key_name}"

        # headers = {"Key": api_key, "Accept": "application/json"}
        # 1. query to info.php to check if the indicator is already in the database
        params = f"indicator={self.observable_name}"
        if hasattr(self, "_api_key_name"):
            params += self.default_param
        resp = requests.get(f"{self.base_url}/info.php?{params}")

        # handle 404 case, submit for analysis
        if resp.status_code == 404 and self.scan_mode != "basic":
            # 2. submit new scan and then poll for result
            result = self.__submit_for_analysis()
        else:
            resp.raise_for_status()
            result = resp.json()

        return result

    def __submit_for_analysis(self) -> dict:
        params = f"value={self.observable_name}&probe={self.probe}"
        if hasattr(self, "_api_key_name"):
            params += self.default_param
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        resp = requests.post(
            f"{self.base_url}/analyze.php", data=params, headers=headers
        )
        resp.raise_for_status()
        qid = resp.json().get("qid", None)
        # 3. retrieve result using qid after waiting for 10 seconds
        params = f"qid={qid}"
        if hasattr(self, "_api_key_name"):
            params += self.default_param
        result = self.__poll_for_result(params)
        if result.get("data", None):
            result = result["data"]

        return result

    def __poll_for_result(self, params):
        result = {}
        url = f"{self.base_url}/analyze.php?{params}"
        obj_repr = self.__repr__()
        for chance in range(self.max_tries):
            logger.info(
                f"polling request #{chance+1} for observable: {self.observable_name}"
                f" <- {obj_repr}"
            )
            time.sleep(self.poll_distance)
            resp = requests.get(url)
            resp.raise_for_status()
            resp_json = resp.json()
            status = resp_json.get("status", None)
            if status == "done":
                result = resp_json
                break
            elif status == "processing":
                continue
            else:
                err = resp_json.get("error", "Report not found.")
                raise AnalyzerRunException(err)

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    side_effect=[
                        MockUpResponse(
                            {}, 404
                        ),  # 404 so `__submit_for_analysis` is called
                        MockUpResponse(
                            {"status": "done", "data": {"test": "test"}}, 200
                        ),
                    ],
                ),
                patch(
                    "requests.post",
                    side_effect=lambda *args, **kwargs: MockUpResponse({"qid": 1}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
