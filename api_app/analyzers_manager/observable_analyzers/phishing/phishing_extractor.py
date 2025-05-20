from logging import getLogger
from typing import Dict

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer
from api_app.choices import Classification
from api_app.models import PythonConfig

logger = getLogger(__name__)


class PhishingExtractor(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "Phishing_Extractor"
    url: str = "http://phishing_analyzers:4005/phishing_extractor"
    max_tries: int = 20
    poll_distance: int = 3

    proxy_address: str = ""
    window_width: int
    window_height: int
    user_agent: str = ""

    def __init__(
        self,
        config: PythonConfig,
        **kwargs,
    ):
        super().__init__(config, **kwargs)
        self.args: [] = []

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        target = self.observable_name
        # handle domain names by appending default
        # protocol. selenium opens only URL types
        if self.observable_classification == Classification.DOMAIN:
            target = "http://" + target
        self.args.append(f"--target={target}")
        if self.proxy_address:
            self.args.append(f"--proxy_address={self.proxy_address}")
        if self.window_width:
            self.args.append(f"--window_width={self.window_width}")
        if self.window_height:
            self.args.append(f"--window_height={self.window_height}")
        if self.user_agent:
            self.args.append(f"--user_agent={self.user_agent}")

    def run(self):
        req_data: {} = {
            "args": [
                *self.args,
            ],
        }
        logger.info(f"sending {req_data=} to {self.url}")
        return self._docker_run(req_data)

    def update(self) -> bool:
        pass
