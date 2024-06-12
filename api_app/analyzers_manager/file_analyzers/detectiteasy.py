import logging

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from tests.mock_utils import MockUpResponse

logger = logging.getLogger(__name__)


class DetectItEasy(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "executable_analyzer"
    url: str = "http://malware_tools_analyzers:4002/die"
    # http request polling max number of tries
    max_tries: int = 10
    # interval between http request polling (in secs)
    poll_distance: int = 1

    def update(self):
        pass

    def run(self):
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        # get the file to send
        binary = self.read_file_bytes()
        args = [f"@{fname}", "--json"]
        req_data = {
            "args": args,
        }
        req_files = {fname: binary}
        logger.info(
            f"Running {self.analyzer_name} on {self.filename} with args: {args}"
        )
        report = self._docker_run(req_data, req_files, analyzer_name=self.analyzer_name)
        if not report:
            self.report.errors.append("DIE did not detect the file type")
            return {}
        return report

    @staticmethod
    def mocked_docker_analyzer_get(*args, **kwargs):
        return MockUpResponse(
            {
                "report": {
                    "arch": "NOEXEC",
                    "mode": "Unknown",
                    "type": "Unknown",
                    "detects": [
                        {
                            "name": "Zip",
                            "type": "archive",
                            "string": "archive: Zip(2.0)[38.5%,1 file]",
                            "options": "38.5%,1 file",
                            "version": "2.0",
                        }
                    ],
                    "filetype": "Binary",
                    "endianess": "LE",
                }
            },
            200,
        )
