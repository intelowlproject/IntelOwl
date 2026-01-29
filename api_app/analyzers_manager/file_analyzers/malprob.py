import logging

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class MalprobScan(FileAnalyzer):
    url: str = "https://malprob.io/api"
    private: bool = False
    timeout: int = 60
    _api_key_name: str

    def update(self):
        pass

    def run(self):
        file_name = str(self.filename).replace("/", "_").replace(" ", "_")
        headers = {"Authorization": f"Token {self._api_key_name}"}
        binary_file = self.read_file_bytes()

        if self._job.tlp == self._job.TLP.CLEAR.value:
            logger.info(f"uploading {file_name}:{self.md5} to MalProb.io for analysis")
            scan = requests.post(
                f"{self.url}/scan/",
                files={"file": binary_file},
                data={"name": file_name, "private": self.private},
                headers=headers,
                timeout=self.timeout,
            )
            scan.raise_for_status()
            if scan.status_code == 204:
                self.disable_for_rate_limit()
                raise AnalyzerRunException("Limit reached for API")
            elif scan.status_code == 302:
                logger.info(f"status 302: file already exists | Rescanning the file: {self.md5}")
            else:
                return scan.json()

        logger.info(f"rescanning {file_name} using {self.md5} on MalProb.io")
        rescan = requests.post(
            f"{self.url}/rescan/",
            data={"hashcode": self.md5},
            headers=headers,
            timeout=self.timeout,
        )
        rescan.raise_for_status()
        if rescan.status_code == 204:
            self.disable_for_rate_limit()
            raise AnalyzerRunException("Limit reached for API")
        return rescan.json()
