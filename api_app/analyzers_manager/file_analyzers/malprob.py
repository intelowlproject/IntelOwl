import logging

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class MalprobScan(FileAnalyzer):
    url: str = "https://malprob.io/api"
    rescan: bool = False
    _api_key_name: str

    def update(self):
        pass

    def run(self):
        response = {}
        file_name = str(self.filename).replace("/", "_").replace(" ", "_")
        headers = {"Authorization": f"Token {self._api_key_name}"}
        binary_file = self.read_file_bytes()

        if not self.rescan:
            logger.info(f"uploading {file_name} to MalProb.io for analysis")
            response["scan"] = requests.post(
                f"{self.url}/scan/",
                files={"file": binary_file},
                data={"name": file_name, "private": False},
                headers=headers,
                timeout=120,
            )
            response["scan"].raise_for_status()
            if response["scan"].status_code == 204:
                raise AnalyzerRunException("Limit reached for API")
            elif response["scan"].status_code == 302:
                raise logger.error(
                    "status 302: file already exists | Rescanning the file"
                )
            else:
                return response["scan"].json()

        logger.info(f"rescanning {file_name} using {self.md5} on MalProb.io")
        response["rescan"] = requests.post(
            f"{self.url}/rescan/",
            data={"hashcode": self.md5},
            headers=headers,
            timeout=120,
        )
        response["rescan"].raise_for_status()
        if response["rescan"].status_code == 204:
            raise AnalyzerRunException("Limit reached for API")
        response["rescan"] = response["rescan"].json()
        return response

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "report": {
                                "md5": "8a05a189e58ccd7275f7ffdf88c2c191",
                                "sha1": "a7a70f2f482e6b26eedcf1781b277718078c743a",
                                "sha256": """ac24043d48dadc390877a6151515565b1fdc1da
                                b028ee2d95d80bd80085d9376""",
                            },
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
