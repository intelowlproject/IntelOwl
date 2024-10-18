import logging

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer
from tests.mock_utils import MockUpResponse

logger = logging.getLogger(__name__)


class GuarddogObservable(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "Guarddog Observable"
    url: str = "http://malware_tools_analyzers:4002/guarddog"
    # http request polling max number of tries
    max_tries: int = 15
    # interval between http request polling (in seconds)
    poll_distance: int = 30

    scan_type: str

    def run(self):

        args = [
            self.scan_type,
            "scan",
            self.observable_name,
        ]
        req_data = {"args": args}

        logger.info(
            f"Running {self.analyzer_name} on {self.observable_name} with args: {args}"
        )
        result = self._docker_run(req_data=req_data, req_files=None)
        return result

    @staticmethod
    def mocked_docker_analyzer_post(*args, **kwargs):
        mockrespose = {
            "key": "test",
            "returncode": 0,
            "report": "Found 0 potentially malicious indicators scanning ... \n",
        }
        return MockUpResponse(mockrespose, 200)
