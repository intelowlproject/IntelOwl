# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class DocGuardUpload(FileAnalyzer):
    url = "https://api.docguard.io:8443/api"
    _api_key_name: str

    def run(self):
        headers = {}
        if hasattr(self, "_api_key_name"):
            headers["x-api-key"] = self._api_key_name
        else:
            warning = "No API key retrieved"
            logger.info(f"{warning}. Continuing without API key... <- {self.__repr__()}")
            self.report.errors.append(warning)

        binary = self.read_file_bytes()
        if not binary:
            raise AnalyzerRunException("File is empty")
        response = requests.post(
            self.url + "/FileAnalyzing/AnalyzeFile",
            headers=headers,
            files={"file": (self.filename, binary)},
        )
        response.raise_for_status()

        return response.json()
