# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import subprocess
from json import dumps, loads
from shlex import quote

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class Floss(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Floss"
    url: str = "http://malware_tools_analyzers:4002/stringsifter"
    # interval between http request polling
    poll_distance: int = 10
    # http request polling max number of tries
    max_tries: int = 60
    # here, max_tries * poll_distance = 10 minutes
    # whereas subprocess timeout is kept as 60 * 9 = 9 minutes
    timeout: int = 60 * 9
    # this is retrieved with bash command `getconf ARG_MAX`
    OS_MAX_ARGS: int = 2097152

    max_no_of_strings: dict
    rank_strings: dict

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        # From floss v3 there is prompt that can be overcome
        # by using the flag --no static.
        # We can lose static strings considering that we can easily
        # retrieve them with more simple tools
        try:
            process: subprocess.CompletedProcess = subprocess.run(
                [
                    "/usr/local/bin/floss",
                    "--json",
                    "--no",
                    "static",
                    "--",
                    quote(self.filepath),
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            result = loads(process.stdout)

        except subprocess.CalledProcessError as e:
            stderr = e.stderr
            logger.info(f"Floss failed to run for {self.filename} with command {e}")
            raise AnalyzerRunException(
                f" Analyzer for {self.filename} failed with error: {stderr}"
            )

        result["exceeded_max_number_of_strings"] = {}

        for key in self.max_no_of_strings:
            if self.rank_strings[key]:
                strings = dumps(result["strings"][key])
                # 4 is the number of arguments that we are already passing
                analyzable_strings = strings[: self.OS_MAX_ARGS - 5]
                args = [
                    "rank_strings",
                    "--limit",
                    str(self.max_no_of_strings[key]),
                    "--strings",
                    analyzable_strings,
                ]
                req_data = {"args": args, "timeout": self.timeout}
                result["strings"][key] = self._docker_run(req_data)
            else:
                if (
                    len(result.get("strings", {}).get(key, []))
                    > self.max_no_of_strings[key]
                ):
                    result["strings"][key] = list(result["strings"][key])
                    result["exceeded_max_number_of_strings"][key] = True
        return result
