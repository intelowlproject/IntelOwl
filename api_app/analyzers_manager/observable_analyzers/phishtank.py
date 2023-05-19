# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64
import logging
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class Phishtank(ObservableAnalyzer):
    _api_key_name: str

    def run(self):
        headers = {"User-Agent": "phishtank/IntelOwl"}
        observable_to_analyze = self.observable_name
        if self.observable_classification == self.ObservableTypes.URL:
            observable_to_analyze = "http://" + urlparse(self.observable_name).hostname

        data = {
            "url": base64.b64encode(observable_to_analyze.encode("utf-8")),
            "format": "json",
        }
        # optional API key
        if not hasattr(self, "_api_key_name"):
            logger.warning(f"{self.__repr__()} -> Continuing w/o API key..")
        else:
            data["app_key"] = self._api_key_name
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
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
