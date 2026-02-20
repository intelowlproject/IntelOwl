# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class DocGuard_Hash(classes.ObservableAnalyzer):
    url: str = "https://api.docguard.net:8443/api/FileAnalyzing/GetByHash/"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    @property
    def hash_type(self):
        hash_lengths = {32: "md5", 64: "sha256"}
        hash_type = hash_lengths.get(len(self.observable_name))
        if not hash_type:
            raise AnalyzerRunException(
                f"Given Hash: '{self.observable_name}' is not supported. Supported hash types are: 'md5', 'sha256'."
            )
        return hash_type

    def run(self):
        headers = {}
        # optional API key
        if hasattr(self, "_api_key_name"):
            headers["x-api-key"] = self._api_key_name
        else:
            warning = "No API key retrieved"
            logger.info(f"{warning}. Continuing without API key... <- {self.__repr__()}")
            self.report.errors.append(warning)

        uri = f"{self.observable_name}"
        if self.observable_classification == Classification.HASH:
            try:
                response = requests.get(self.url + uri, headers=headers)
                response.raise_for_status()
            except requests.RequestException as e:
                raise AnalyzerRunException(e)
        else:
            raise AnalyzerRunException("Please use hash")

        result = response.json()
        return result
