from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer, DockerBasedAnalyzer


class Qiling(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Qiling"
    url: str = "http://qiling:4005/qiling"
    # http request polling max number of tries
    max_tries: int = 15
    # interval between http request polling (in secs)
    poll_distance: int = 30

    def set_config(self, additional_config_params):
        self.args = []
        os = additional_config_params.get("os", "x86")
        arch = additional_config_params.get("arch", "windows")
        self.args.extend([os] + [arch])
        shellcode = additional_config_params.get("shellcode", False)
        if shellcode:
            self.args.append("--shellcode")
        profile = additional_config_params.get("profile", None)
        if profile:
            self.args.extend(["--profile"] + [profile])

    def run(self):
        # get the file to send
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        binary = get_binary(self.job_id)
        # make request parameters
        req_data = {"args": [f"@{fname}"] + self.args}
        req_files = {fname: binary}
        return self._docker_run(req_data, req_files)
