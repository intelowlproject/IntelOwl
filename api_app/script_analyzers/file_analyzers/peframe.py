import requests
import json

from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer, DockerBasedAnalyzer
from api_app.exceptions import AnalyzerConfigurationException


class PEframe(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "PEframe"
    url: str = "http://peframe:4000/peframe"

    def set_config(self, additional_config_params):
        # http request polling max number of tries
        self.max_tries: int = additional_config_params.get("max_tries", 15)
        # interval between http request polling
        self.poll_distance: int = additional_config_params.get("poll_distance", 5)

    def run(self):
        # get binary
        binary = get_binary(self.job_id)
        # make request data
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        req_data = {"args": ["-j", f"@{fname}"]}
        req_files = {fname: binary}

        # step #1: request new analysis
        try:
            resp1 = requests.post(self.url, files=req_files, data=req_data)
        except requests.exceptions.ConnectionError:
            raise AnalyzerConfigurationException(
                f"{self.name} docker container is not running."
            )

        # step #2: raise AnalyzerRunException in case of error
        assert self._raise_in_case_bad_request(self.name, resp1)

        # step #3: if no error, continue and try to fetch result
        key = resp1.json().get("key", None)
        result_resp = self._poll_for_result(key)
        result = result_resp.get("report", None)
        if result:
            result = json.loads(result)
            # limit strings dump to first 100
            if "strings" in result and "dump" in result["strings"]:
                result["strings"]["dump"] = result["strings"]["dump"][:100]

        return result
