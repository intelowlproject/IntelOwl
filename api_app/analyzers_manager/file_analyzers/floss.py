# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from json import dumps as json_dumps

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer


class Floss(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Floss"
    url: str = "http://static_analyzers:4002/floss"
    ranking_url: str = "http://static_analyzers:4002/stringsifter"
    # interval between http request polling
    poll_distance: int = 10
    # http request polling max number of tries
    max_tries: int = 60
    # here, max_tries * poll_distance = 10 minutes
    timeout: int = 60 * 9
    # whereas subprocess timeout is kept as 60 * 9 = 9 minutes

    def set_params(self, params):
        self.max_no_of_strings = params.get(
            "max_no_of_strings",
            {"stack_strings": 1000, "static_strings": 1000, "decoded_strings": 1000},
        )
        self.rank_strings = params.get(
            "rank_strings",
            {"stack_strings": False, "static_strings": False, "decoded_strings": False},
        )

    def run(self):
        # get binary
        binary = self.read_file_bytes()
        # make request data
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = [f"@{fname}", f"--output-json=/tmp/{fname}.json"]
        req_data = {
            "args": args,
            "timeout": self.timeout,
            "callback_context": {"read_result_from": fname},
        }
        req_files = {fname: binary}
        result = self._docker_run(req_data, req_files)
        result["exceeded_max_number_of_strings"] = {}

        self.url = self.ranking_url
        for key in self.max_no_of_strings.keys():
            if self.rank_strings[key]:
                args = [
                    "rank_strings",
                    "--limit",
                    str(self.max_no_of_strings[key]),
                    "--strings",
                    json_dumps(result["strings"][key]),
                ]
                req_data = {"args": args, "timeout": self.timeout}
                result["strings"][key] = self._docker_run(req_data)
            else:
                if (
                    len(result.get("strings", {}).get(key, []))
                    > self.max_no_of_strings[key]
                ):
                    result["strings"][key] = [s for s in result["strings"][key]]
                    result["exceeded_max_number_of_strings"][key] = True
        return result
