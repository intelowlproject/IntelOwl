import logging

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer

logger = logging.getLogger(__name__)


class DroidLysis(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "android_analyzer"
    url: str = "http://malware_tools_analyzers:4002/droidlysis"
    # interval between http request polling
    poll_distance: int = 2
    # http request polling max number of tries
    max_tries: int = 30

    def update(self) -> bool:
        pass

    def run(self):
        binary = self.read_file_bytes()
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = [
            "--input",
            f"@{fname}",
            "-o",
            "/opt/deploy/droidlysis/out/",
            "--config",
            "/opt/deploy/droidlysis/conf/general.conf",
        ]
        req_data = {"args": args}
        req_files = {fname: binary}
        logger.info(f"Running {self.analyzer_name} on {self.filename} with args: {args}")
        result = self._docker_run(req_data, req_files, analyzer_name=self.analyzer_name)
        return result
