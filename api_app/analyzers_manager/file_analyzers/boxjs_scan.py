# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer


class BoxJS(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "box-js"
    url: str = "http://malware_tools_analyzers:4002/boxjs"
    # http request polling max number of tries
    max_tries: int = 5
    # interval between http request polling (in secs)
    poll_distance: int = 12

    def run(self):
        # construct a valid filename into which thug will save the result
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        # get the file to send
        binary = self.read_file_bytes()
        # construct arguments, For example this corresponds to,
        # box-js sample.js --output-dir=/tmp/boxjs --no-kill ...
        args = [
            f"@{fname}",
            "--output-dir=/tmp/boxjs",
            "--no-kill",
            "--no-shell-error",
            "--no-echo",
        ]
        # Box-js by default has a timeout of 10 seconds,
        # but subprocess is not able to catch that
        # that's why it's necessary to provide a custom timeout of
        # 10 seconds only to the subprocess itself.
        req_data = {
            "args": args,
            "timeout": 10,
            "callback_context": {"read_result_from": fname},
        }
        req_files = {fname: binary}

        return self._docker_run(req_data, req_files)
