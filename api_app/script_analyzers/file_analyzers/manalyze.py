from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer, DockerBasedAnalyzer


class Manalyze(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Manalyze"
    url: str = "http://static_analyzers:4002/manalyze"
    # interval between http request polling
    poll_distance: int = 10
    # http request polling max number of tries
    max_tries: int = 60
    # here, max_tries * poll_distance = 10 minutes
    timeout: int = 60 * 9
    # whereas subprocess timeout is kept as 60 * 9 = 9 minutes

    def run(self):
        # get binary
        binary = get_binary(self.job_id)
        # make request data
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = [f"@{fname}", "--output", "json"]
        req_data = {
            "args": args,
            "timeout": self.timeout,
        }
        req_files = {fname: binary}
        report = self._docker_run(req_data, req_files)
        return report.values()
