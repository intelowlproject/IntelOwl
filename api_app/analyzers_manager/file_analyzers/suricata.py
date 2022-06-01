# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer


class Suricata(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Suricata"
    url: str = "http://pcap_analyzers:4004/suricata"
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
        # the result file is the same one that should be configured in suricata.yml
        req_data = {
            "args": args,
            "timeout": self.timeout,
            "callback_context": {"read_result_from": "/tmp/eve.json"},
        }
        req_files = {fname: binary}

        report = self._docker_run(req_data, req_files)
        print(report)

        result = {}

        return result
