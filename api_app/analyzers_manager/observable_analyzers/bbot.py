# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from api_app.models import PythonConfig
from tests.mock_utils import MockUpResponse

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class BBOT(ObservableAnalyzer, DockerBasedAnalyzer):
    """
    BBOT Docker-based analyzer for IntelOwl.
    """

    name: str = "BBOT_Analyzer"
    url: str = "http://bbot_analyzer:5001/run"
    max_tries: int = 25
    poll_distance: int = 5

    def __init__(self, config: PythonConfig, **kwargs):
        super().__init__(config, **kwargs)
        self.args: list[str] = []

    def config(self, runtime_configuration: dict):
        super().config(runtime_configuration)
        target = self.observable_name

        if self.observable_classification == Classification.URL:
            logger.debug(f"Extracting hostname from URL: {target}")
            target = urlparse(target).hostname

        self.args.append(f"-t {target}")
        self.args.extend([f"-p {preset}" for preset in self.presets])
        self.args.extend([f"-m {module}" for module in self.modules])

    def run(self):
        """
        Executes BBOT inside the Docker container via HTTP API.
        """
        req_data = {
            "target": self.observable_name,
            "presets": self.presets,
            "modules": self.modules,
        }

        logger.info(f"Sending {self.name} scan request: {req_data} to {self.url}")

        try:
            report = self._docker_run(req_data, analyzer_name=self.name)
            logger.info(f"BBOT scan completed successfully with report: {report}")
            return report
        except requests.RequestException as e:
            logger.error(f"BBOT HTTP request failed: {e}")
            raise AnalyzerRunException(f"Network error contacting BBOT container: {e}")

    @classmethod
    def update(cls):
        pass

    @staticmethod
    def mocked_docker_analyzer_post(*args, **kwargs):
        mock_response = {
            "success": True,
            "report": {
                "events": [
                    {
                        "id": "SCAN:7804fe5d0d26eec716926da9a4002d4ceb171300",
                        "name": "melodramatic_todd",
                        "preset": {
                            "flags": ["iis-shortnames", "web-basic"],
                            "config": {
                                "modules": {"iis_shortnames": {"detect_only": False}}
                            },
                            "description": "melodramatic_todd",
                            "output_modules": ["json"],
                        },
                        "status": "FINISHED",
                        "target": {
                            "hash": "a2d3b5795582da7a4edc56ef63ae6d6866a70d9c",
                            "seeds": ["test.com"],
                            "blacklist": [],
                            "seed_hash": "1f26e4e291bfa260f77d2411c88906aee99786c5",
                            "whitelist": ["test.com"],
                            "scope_hash": "86df039469ae73720ac0d8cdd7cf92c3953659b4",
                            "strict_scope": False,
                            "blacklist_hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            "whitelist_hash": "1f26e4e291bfa260f77d2411c88906aee99786c5",
                        },
                        "duration": "52 seconds",
                        "started_at": "2025-03-18T14:30:59.131139",
                        "finished_at": "2025-03-18T14:31:51.854936",
                        "duration_seconds": 52.723797,
                    }
                ],
                "json_output": [],
            },
        }
        return MockUpResponse(mock_response, 200)
