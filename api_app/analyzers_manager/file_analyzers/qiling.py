# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer


class Qiling(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Qiling"
    url: str = "http://qiling:4005/qiling"
    # http request polling max number of tries
    max_tries: int = 15
    # interval between http request polling (in secs)
    poll_distance: int = 30

    def set_params(self, params):
        self.args = []
        os = params.get("os", "windows")
        arch = params.get("arch", "x86")
        self.args.extend([os] + [arch])
        shellcode = params.get("shellcode", False)
        if shellcode:
            self.args.append("--shellcode")
        profile = params.get("profile", None)
        if profile:
            self.args.extend(["--profile"] + [profile])

    def run(self):
        # get the file to send
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        binary = self.read_file_bytes()
        # make request parameters
        req_data = {"args": [f"@{fname}", *self.args]}
        req_files = {fname: binary}
        return self._docker_run(req_data, req_files)
