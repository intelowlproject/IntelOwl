from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer, DockerBasedAnalyzer


class PEframe(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "PEframe"
    url: str = "http://static_analyzers:4002/peframe"
    # http request polling max number of tries
    max_tries: int = 25
    # interval between http request polling
    poll_distance: int = 5

    def run(self):
        # get binary
        binary = get_binary(self.job_id)
        # make request data
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        req_data = {"args": ["-j", f"@{fname}"]}
        req_files = {fname: binary}

        result = self._docker_run(req_data, req_files)

        if result:
            # limit strings dump to first 100
            if "strings" in result and "dump" in result["strings"]:
                result["strings"]["dump"] = result["strings"]["dump"][:100]

        return result
