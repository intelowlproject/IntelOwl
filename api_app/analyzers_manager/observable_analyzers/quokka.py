# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import json
from logging import getLogger

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerConfigurationException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = getLogger(__name__)


class Quokka(ObservableAnalyzer):
    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        if not self.__api_key:
            raise AnalyzerConfigurationException("API key is required")
        self.__certificate = self._secrets.get("certificate", None)
        if self.__certificate is None:
            self.__certificate = False
        self.__url = self._secrets["url"]
        if not self.__url:
            raise AnalyzerConfigurationException("Quokka URL is required")
        self.reduced = params.get("reduced", True)
        self.public = params.get("public", True)

    def run(self):
        headers = {
            "Authorization": f"Token {self.__api_key}",
            "Accept": "application/json",
        }
        params_ = {
            "is_public_analysis": self.public,
            "reduced": self.reduced,
            "md5": self._job.md5,
        }
        logger.info(params_)
        response = requests.get(
            self.__url, params=params_, headers=headers, verify=self.__certificate
        )
        response.raise_for_status()

        result = json.loads(response.json())
        logger.info(result)
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse("{}", 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
