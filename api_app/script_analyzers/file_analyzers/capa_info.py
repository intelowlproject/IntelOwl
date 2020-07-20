import requests
import json
import logging

from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer, DockerBasedAnalyzer
from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException

logger = logging.getLogger(__name__)


class CapaInfo(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Capa"
    url: str = "http://capa:4002/capa"
    # interval between http request polling
    poll_distance: int = 10
    # http request polling max number of tries
    max_tries: int = 30
    # here, max_tries * poll_distance = 5 minutes

    def run(self):
        # get binary
        binary = get_binary(self.job_id)
        # make request data
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = [f"@{fname}", "-j"]
        req_data = {"args": args}
        req_files = {fname: binary}

        # step #1: request new analysis
        logger.debug(f"Making request with arguments: {args} <- {self.__repr__()}")
        try:
            resp = requests.post(self.url, files=req_files, data=req_data)
        except requests.exceptions.ConnectionError:
            raise AnalyzerConfigurationException(
                f"{self.name} docker container is not running."
            )

        # step #2: raise AnalyzerRunException in case of error
        assert self._raise_in_case_bad_request(self.name, resp)

        # step #3: if no error, continue and try to fetch result
        key = resp.json().get("key", None)
        final_resp = self._poll_for_result(key)
        result = final_resp.get("report", None)
        status = final_resp.get("status", None)
        if isinstance(result, dict):
            return result

        try:
            result = json.loads(result)
            if status:
                self.report["status"] = status
        except json.JSONDecodeError:
            raise AnalyzerRunException(final_resp.get("error", None))

        return result
