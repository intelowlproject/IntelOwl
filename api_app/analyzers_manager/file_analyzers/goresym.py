import logging

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class GoReSym(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "executable_analyzer"
    url: str = "http://malware_tools_analyzers:4002/goresym"
    # interval between http request polling
    poll_distance: int = 5
    # http request polling max number of tries
    max_tries: int = 5
    flags: str = "-t -d -p"

    def update(self) -> bool:
        pass

    def run(self):
        binary = self.read_file_bytes()
        fname = str(self.filename).replace("/", "_").replace(" ", "_")

        args = []
        args.extend(self.flags.split(" "))
        args.append(f"@{fname}")
        req_data = {"args": args}
        req_files = {fname: binary}
        logger.info(
            f"Running {self.analyzer_name} on {self.filename} with args: {args}"
        )
        result = self._docker_run(req_data, req_files, analyzer_name=self.analyzer_name)
        if "error" in result:
            raise AnalyzerRunException(result["error"])

        return result
