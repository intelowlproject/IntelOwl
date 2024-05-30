import logging

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer

logger = logging.getLogger(__name__)


class DetectItEasy(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "executable_analyzer"
    url: str = "http://malware_tools_analyzers:4002/die"
    # http request polling max number of tries
    max_tries: int = 10
    # interval between http request polling (in secs)
    poll_distance: int = 3

    def run(self):
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        # get the file to send
        binary = self.read_file_bytes()
        args = [f"@{fname}", "--json"]
        req_data = {
            "args": args,
        }
        req_files = {fname: binary}
        logger.info(f"Running {self.analyzer_name} with args: {args}")
        report = self._docker_run(req_data, req_files, analyzer_name=self.analyzer_name)
        if not report:
            self.report.errors.append("DIE does not support the file")
            return {}
        return report
