from logging import getLogger
from typing import Dict

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.models import PythonConfig

logger = getLogger(__name__)


class PhishingAnalyzer(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "PhishingAnalyzer"
    url: str = "http://phishing_analyzers:4005/phishing_analyzers"
    max_tries: int = 20
    poll_distance: int = 3

    proxy_protocol: str = ""
    proxy_address: str = ""
    proxy_port: int = 0
    headless: bool = True

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

        if self.headless:
            self.args.append("--headless")
        else:
            self.args.append("--no-headless")

    def run(self):
        req_data = {"args": [*self.args]}
        report = self._docker_run(req_data)
        if report.get("setup_error"):
            raise AnalyzerRunException(report["setup_error"])
        if report.get("execution_error"):
            raise AnalyzerRunException(report["execution_error"])
        return report
