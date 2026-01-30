# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from api_app.models import PythonConfig

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
            report = self._docker_run(req_data, analyzer_name=self.name, avoid_polling=True)
            logger.info(f"BBOT scan completed successfully with report: {report}")
            return report
        except requests.RequestException as e:
            logger.error(f"BBOT HTTP request failed: {e}")
            raise AnalyzerRunException(f"Network error contacting BBOT container: {e}")

    @classmethod
    def update(cls):
        pass
