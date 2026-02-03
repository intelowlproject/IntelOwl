# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from typing import List

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer

logger = logging.getLogger(__name__)


class BoxJS(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "box-js"
    url: str = "http://malware_tools_analyzers:4002/boxjs"
    # http request polling max number of tries
    max_tries: int = 5
    # interval between http request polling (in secs)
    poll_distance: int = 12

    @classmethod
    def update(cls) -> bool:
        pass

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
        report = self._docker_run(req_data, req_files)

        report["uris"] = []
        if "urls.json" in report and isinstance(report["urls.json"], List):
            report["uris"].extend(report["urls.json"])
        if "active_urls.json" in report and isinstance(report["active_urls.json"], List):
            report["uris"].extend(report["active_urls.json"])
        if "IOC.json" in report and isinstance(report["IOC.json"], List):
            for ioc in report["IOC.json"]:
                try:
                    if "url" in ioc["type"].lower():
                        report["uris"].append(ioc["value"]["url"])
                except KeyError:
                    error_message = f"job_id {self.job_id} JSON structure changed in BoxJS report"
                    logger.warning(error_message, stack_info=True)
                    self.report.errors.append(error_message)
        report["uris"] = list(set(report["uris"]))  # uniq

        return report
