import requests
import logging

from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer, DockerBasedAnalyzer
from api_app.exceptions import AnalyzerRunException
from ..observable_analyzers.thug_url import ThugUrl

logger = logging.getLogger(__name__)


class ThugFile(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Thug"
    base_url: str = "http://thug:4001"
    url: str = "http://thug:4001/thug"
    # http request polling max number of tries
    max_tries: int = 7
    # interval between http request polling (in secs)
    poll_distance: int = 60

    def set_config(self, additional_config_params):
        self.args = ThugUrl._thug_args_builder(additional_config_params)

    def run(self):
        # get binary
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        self.args.extend(["-n", "/tmp/thug/" + fname, "-l", f"@{fname}"])
        logger.debug(f"Making request with arguments: {self.args} <- {repr(self)}")
        # step #1: request new analysis
        resp1 = requests.post(
            self.url, files={fname: get_binary(self.job_id)}, data={"args": self.args,},
        )
        # handle cases in case of error
        if self._check_status_code(self.name, resp1):
            # if no error, continue..
            errors = []
            # step #2: this is to check whether analysis completed or not..
            key = resp1.json().get("key", None)
            if not key:
                if self.is_test:
                    # if this is a test, then just return here..
                    return {}
                # else raise exception
                raise AnalyzerRunException(
                    "Unexpected Error. "
                    "Please check log files under /var/log/intel_owl/thug/"
                )
            resp2 = self._poll_for_result(key)
            err = resp2.get("error", None)
            if err:
                # this may return error, but we can still try to fetch report
                errors.append(err)

            logger.info(f"Fetching final report <-- {self.__repr__()}")
            # step #3: try to fetch the final report..
            result_resp = requests.get(f"{self.base_url}/get-result?name={fname}")
            if not result_resp.status_code == 200:
                e = result_resp.json().get("error", "")
                errors.append(e)
                raise AnalyzerRunException(", ".join(errors))

            return result_resp.json()
