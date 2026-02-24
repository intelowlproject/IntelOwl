from logging import getLogger

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer
from api_app.choices import Classification
from api_app.models import PythonConfig

logger = getLogger(__name__)

_PHISHING_BASE_URL = "http://phishing_analyzers:4005"
_ENGINE_ENDPOINTS = {
    "selenium": f"{_PHISHING_BASE_URL}/phishing_extractor",
    "playwright": f"{_PHISHING_BASE_URL}/phishing_extractor_playwright",
}


class PhishingExtractor(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "Phishing_Extractor"
    url: str = _ENGINE_ENDPOINTS["selenium"]
    max_tries: int = 20
    poll_distance: int = 3

    proxy_address: str = ""
    window_width: int
    window_height: int
    user_agent: str = ""
    phishing_engine: str = "selenium"

    def __init__(
        self,
        config: PythonConfig,
        **kwargs,
    ):
        super().__init__(config, **kwargs)
        self.args: list = []

    def config(self, runtime_configuration: dict):
        super().config(runtime_configuration)

        engine = self.phishing_engine.lower().strip()
        if engine not in _ENGINE_ENDPOINTS:
            logger.warning(f"Unknown phishing_engine={engine!r}, falling back to 'selenium'")
            engine = "selenium"
        self.url = _ENGINE_ENDPOINTS[engine]
        logger.info(f"Phishing engine set to {engine!r} -> {self.url}")

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
        req_data: dict = {
            "args": self.args,
        }
        logger.info(f"sending {req_data=} to {self.url}")
        return self._docker_run(req_data)

    def update(self) -> bool:
        pass
