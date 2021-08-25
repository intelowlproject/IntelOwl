# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import FileAnalyzer, DockerBasedAnalyzer


class ClamAV(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "ClamAV"
    url: str = "http://static_analyzers:4002/clamav"
    # interval between http request polling
    poll_distance: int = 3
    # http request polling max number of tries
    max_tries: int = 5
    # timeout limit
    timeout: int = 15

    def run(self):
        # get binary
        binary = self.read_file_bytes()
        # make request data
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = [f"@{fname}"]
        req_data = {"args": args, "timeout": self.timeout}
        req_files = {fname: binary}

        report = self._docker_run(req_data, req_files)

        ok = "OK" in report
        val = report.split("\n")[0].split()[1]
        found = None if val == "OK" else val

        return {"ok": ok, "found": found, "raw_report": report}
