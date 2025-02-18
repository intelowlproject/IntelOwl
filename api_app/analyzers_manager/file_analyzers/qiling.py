# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Dict

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class Qiling(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Qiling"
    url: str = "http://malware_tools_analyzers:4002/qiling"
    # http request polling max number of tries
    max_tries: int = 15
    # interval between http request polling (in secs)
    poll_distance: int = 30
    timeout: int = 60 * 9
    # whereas subprocess timeout is kept as 60 * 9 = 9 minutes

    os: str
    arch: str
    shellcode: bool
    profile: str

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.args = [self.os, self.arch]
        if self.shellcode:
            self.args.append("--shellcode")
        if self.profile:
            self.args.extend(["--profile"] + [self.profile])

    def run(self):
        # get the file to send
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        binary = self.read_file_bytes()
        # make request parameters
        req_data = {"args": [f"@{fname}", *self.args], "timeout": self.timeout}
        req_files = {fname: binary}
        report = self._docker_run(req_data, req_files)
        if report.get("setup_error"):
            raise AnalyzerRunException(report["setup_error"])
        if report.get("execution_error"):
            raise AnalyzerRunException(report["execution_error"])
        if report.get("qiling_not_available_error"):
            raise AnalyzerRunException(report["qiling_not_available_error"])
        return report
