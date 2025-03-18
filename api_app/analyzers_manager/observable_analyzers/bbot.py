import logging
from typing import Dict, List
from urllib.parse import urlparse

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from api_app.models import PythonConfig
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class BBOT(ObservableAnalyzer, DockerBasedAnalyzer):
    """
    BBOT Docker-based analyzer for IntelOwl.
    """

    name: str = "BBOT_Analyzer"
    url: str = "http://bbot_analyzer:5000/run"
    max_tries: int = 100
    poll_distance: int = 3

    def __init__(self, config: PythonConfig, **kwargs):
        super().__init__(config, **kwargs)
        self.args: List[str] = []

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        target = self.observable_name

        if self.observable_classification == Classification.URL:
            logger.debug(f"Extracting hostname from URL: {target}")
            hostname = urlparse(target).hostname
            target = hostname

        # Prepare arguments for BBOT API request
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

        logger.info(f"Sending BBOT scan request: {req_data} to {self.url}")

        try:
            response = self._docker_run(req_data)
            logger.debug(f"BBOT response: {response}")
            return response
        except Exception as e:
            raise AnalyzerRunException(f"BBOT analyzer failed: {e}")

    def update(self):
        pass

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "bbot.scanner.Scanner.start",
                    return_value=MockUpResponse(
                        {
                            "status": "success",
                            "data": "example.com. 236 IN A 23.215.0.138",
                            "message": "DNS query for example.com completed successfully.",
                        },
                        200,
                        content=b"pn\x01\x03\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
                    ),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
