import requests
import json

from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer, DockerBasedAnalyzer
from api_app.exceptions import AnalyzerRunException


class PEframe(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "PEframe"
    url: str = "http://peframe:4000/peframe"
    # interval between http request polling
    poll_distance: int = 5

    def set_config(self, additional_config_params):
        # http request polling max number of tries
        self.max_tries: int = int(additional_config_params.get("max_tries", 15))

    def run(self):
        # get binary
        binary = get_binary(self.job_id)
        # request new analysis
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        req_data = {"args": ["-j", f"@{fname}"]}
        req_files = {fname: binary}
        r = requests.post(self.url, files=req_files, data=req_data)
        # handle cases in case of error
        if self._check_status_code(self.name, r):
            # if no error, continue..
            # this is to check whether analysis completed or not..
            key = r.json().get("key", None)
            if not key:
                raise AnalyzerRunException(
                    "Unexpected Error. "
                    "Please check log files under /var/log/intel_owl/peframe/"
                )
            resp = self._poll_for_result(key)
            result = resp.get("report", None)
            if result:
                result = json.loads(result)
                # limit strings dump to first 100
                if "strings" in result and "dump" in result["strings"]:
                    result["strings"]["dump"] = result["strings"]["dump"][:100]

            return result
