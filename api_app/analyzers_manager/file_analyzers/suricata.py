# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer


class Suricata(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Suricata"
    url: str = "http://pcap_analyzers:4004/suricata"
    # interval between http request polling
    poll_distance: int = 3
    # http request polling max number of tries
    max_tries: int = 100
    # timeout limit
    timeout: int = 200

    def set_params(self, params):
        self.verbose = params.get("verbose", True)

    def run(self):
        # get binary
        binary = self.read_file_bytes()
        # make request data
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = [f"@{fname}", f"{self.md5}"]
        # the result file is the same one that should be configured in suricata.yml
        req_data = {
            "args": args,
            "timeout": self.timeout,
            "callback_context": {"read_result_from": f"/tmp/eve_{self.md5}"},
        }
        req_files = {fname: binary}

        report = self._docker_run(req_data, req_files)
        # normalize signature names to facilitate analysis
        signatures = []
        for detection in report["data"]:
            signature = detection.get("alert", {}).get("signature")
            if signature:
                signatures.append(signature)
        # remove duplicates
        report["signatures"] = list(set(signatures))

        return report
