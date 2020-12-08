from json import dumps as json_dumps
from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer, DockerBasedAnalyzer


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

    def set_config(self, additional_config_params):
        self.max_no_of_strings = int(
            additional_config_params.get("max_number_of_strings", 300)
        )
        self.max_chars_for_string = int(
            additional_config_params.get("max_characters_for_string", 1000)
        )

        # If set, this module will use Machine Learning feature
        # CARE!! ranked_strings could be cpu/ram intensive and very slow
        self.rank_strings = additional_config_params.get("rank_strings", False)

    def run(self):
        # get binary
        binary = get_binary(self.job_id)
        # make request data
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = ["flarestrings", f"@{fname}"]
        req_data = {
            "args": args,
            "timeout": self.timeout,
        }
        req_files = {fname: binary}
        result = self._docker_run(req_data, req_files)

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
            result = {"data": result, "exceeded_max_number_of_strings": False}
        elif len(result) > self.max_no_of_strings:
            result = [s for s in result[: self.max_no_of_strings]]
            result = {"data": result, "exceeded_max_number_of_strings": True}
        result["data"] = [
            row[: self.max_chars_for_string] for row in result.get("data", [])
        ]
        return result
