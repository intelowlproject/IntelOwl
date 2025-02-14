import logging

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from tests.mock_utils import MockUpResponse

logger = logging.getLogger(__name__)


class GuarddogFile(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Guarddog"
    url: str = "http://malware_tools_analyzers:4002/guarddog"
    # http request polling max number of tries
    max_tries: int = 15
    # interval between http request polling (in secs)
    poll_distance: int = 30

    scan_type: str

    def run(self):
        binary = self.read_file_bytes()
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = [
            self.scan_type,
            "scan",
            f"@{fname}",
        ]
        req_data = {"args": args}
        req_files = {fname: binary}
        logger.info(
            f"Running {self.analyzer_name} on {self.filename} with args: {args}"
        )
        result = self._docker_run(req_data, req_files, analyzer_name=self.analyzer_name)
        return result

    @staticmethod
    def mocked_docker_analyzer_get(*args, **kwargs):
        return MockUpResponse(
            {
                "key": "test",
                "returncode": 0,
                "report": "Found 0 potentially malicious indicators scanning ... \n",
            },
            200,
        )
