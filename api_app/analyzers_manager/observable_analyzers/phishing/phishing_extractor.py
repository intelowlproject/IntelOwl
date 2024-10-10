from logging import getLogger
from typing import Dict

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer
from api_app.models import PythonConfig

logger = getLogger(__name__)


class PhishingExtractor(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "Phishing_Extractor"
    url: str = "http://phishing_analyzers:4005/phishing_extractor"
    max_tries: int = 20
    poll_distance: int = 3

    proxy_protocol: str = ""
    proxy_address: str = ""
    proxy_port: int = 0

    def __init__(
        self,
        config: PythonConfig,
        **kwargs,
    ):
        super().__init__(config, **kwargs)
        self.args: list = []

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        if self.proxy_address:
            self.args.append(f"--proxy_address={self.proxy_address}")
            if self.proxy_protocol:
                self.args.append(f"--proxy_protocol={self.proxy_protocol}")
            if self.proxy_port:
                self.args.append(f"--proxy_port={self.proxy_port}")

    def run(self):
        req_data: {} = {
            "args": [
                f"--target={self.observable_name}",
                *self.args,
            ],
        }
        logger.info(f"sending {req_data=} to {self.url}")
        return self._docker_run(req_data)

    def update(self) -> bool:
        pass
