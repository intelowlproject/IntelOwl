# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Dict

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer


class CapaInfo(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Capa"
    url: str = "http://malware_tools_analyzers:4002/capa"
    # interval between http request polling
    poll_distance: int = 10
    # http request polling max number of tries
    max_tries: int = 60
    # here, max_tries * poll_distance = 10 minutes
    timeout: int = 60 * 9
    # whereas subprocess timeout is kept as 60 * 9 = 9 minutes

    shellcode: bool
    arch: str

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.args = []
        if self.arch != "64":
            self.arch = "32"
        if self.shellcode:
            self.args.append("-f")
            self.args.append("sc" + self.arch)

    def run(self):
        # get binary
        binary = self.read_file_bytes()
        # make request data
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = [f"@{fname}", *self.args]
        req_data = {"args": args, "timeout": self.timeout}
        req_files = {fname: binary}

        return self._docker_run(req_data, req_files)
