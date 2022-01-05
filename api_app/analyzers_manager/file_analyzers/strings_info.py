# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from json import dumps as json_dumps

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer


class StringsInfo(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "StringsInfo"
    url: str = "http://static_analyzers:4002/stringsifter"
    # interval between http request polling
    poll_distance: int = 10
    # http request polling max number of tries
    max_tries: int = 60
    # here, max_tries * poll_distance = 10 minutes
    timeout: int = 60 * 9
    # whereas subprocess timeout is kept as 60 * 9 = 9 minutes

    def set_params(self, params):
        self.max_no_of_strings = int(params.get("max_number_of_strings", 300))
        self.max_chars_for_string = int(params.get("max_characters_for_string", 1000))

        # If set, this module will use Machine Learning feature
        # CARE!! ranked_strings could be cpu/ram intensive and very slow
        self.rank_strings = params.get("rank_strings", False)

    def run(self):
        # get binary
        binary = self.read_file_bytes()
        # make request data
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = ["flarestrings", f"@{fname}"]
        req_data = {
            "args": args,
            "timeout": self.timeout,
        }
        req_files = {fname: binary}
        result = self._docker_run(req_data, req_files)
        exceed_max_strings = len(result) > self.max_no_of_strings
        if exceed_max_strings:
            result = list(result[: self.max_no_of_strings])
        if self.rank_strings:
            args = [
                "rank_strings",
                "--limit",
                str(self.max_no_of_strings),
                "--strings",
                json_dumps(result),
            ]
            req_data = {"args": args, "timeout": self.timeout}
            result = self._docker_run(req_data)
        result = {
            "data": [row[: self.max_chars_for_string] for row in result],
            "exceeded_max_number_of_strings": exceed_max_strings,
        }
        return result
