# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from json import dumps as json_dumps

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class Floss(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Floss"
    url: str = "http://malware_tools_analyzers:4002/floss"
    ranking_url: str = "http://malware_tools_analyzers:4002/stringsifter"
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
        # get binary
        binary = self.read_file_bytes()
        # make request data
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        # From floss v3 there is prompt that can be overcome
        # by using the flag --no static.
        # We can lose static strings considering that we can easily
        # retrieve them with more simple tools
        args = [f"@{fname}", "--json", "--no", "static"]
        req_data = {"args": args, "timeout": self.timeout}
        req_files = {fname: binary}
        result = self._docker_run(req_data, req_files)
        if not isinstance(result, dict):
            raise AnalyzerRunException(
                f"result from floss tool is not a dict but is {type(result)}."
                f" Full dump: {result}"
            )
        result["exceeded_max_number_of_strings"] = {}
        # we are changing the endpoint of _docker_run to stringsifter
        self.url = self.ranking_url

        for key in self.max_no_of_strings:
            if self.rank_strings[key]:
                strings = json_dumps(result["strings"][key])
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
