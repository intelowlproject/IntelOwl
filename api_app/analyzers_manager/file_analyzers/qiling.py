# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from api_app.exceptions import AnalyzerRunException


class Qiling(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Qiling"
    url: str = "http://malware_tools_analyzers:4002/qiling"
    # http request polling max number of tries
    max_tries: int = 15
    # interval between http request polling (in secs)
    poll_distance: int = 30
    timeout: int = 60 * 9
    # whereas subprocess timeout is kept as 60 * 9 = 9 minutes

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
        req_data = {"args": [f"@{fname}", *self.args], "timeout": self.timeout}
        req_files = {fname: binary}
        report = self._docker_run(req_data, req_files)
        if report.get("setup_error"):
            raise AnalyzerRunException(report["setup_error"])
        if report.get("execution_error"):
            raise AnalyzerRunException(report["execution_error"])
        return report
