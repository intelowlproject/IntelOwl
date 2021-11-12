# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64
import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class Phishtank(ObservableAnalyzer):
    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        result = {}
        headers = {"User-Agent": "phishtank/IntelOwl"}
        data = {
            "url": base64.b64encode(self.observable_name.encode("utf-8")),
            "format": "json",
        }
        # optional API key
        if not self.__api_key:
            logger.warning(f"{self.__repr__()} -> Continuing w/o API key..")
        else:
            data["app_key"] = self.__api_key
        try:
            resp = requests.post(
                "https://checkurl.phishtank.com/checkurl/", data=data, headers=headers
            )
            resp.raise_for_status()
            result = resp.json()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
