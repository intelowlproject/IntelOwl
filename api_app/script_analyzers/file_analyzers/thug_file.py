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
        logger.debug(
            f"Making request with arguments: {self.args}"
            f" for analyzer: {self.analyzer_name}, job_id: #{self.job_id}."
        )
        # request new analysis
        r = requests.post(
            self.url, files={fname: get_binary(self.job_id)}, data={"args": self.args,},
        )
        # handle cases in case of error
        if self._check_status_code(self.name, r):
            # if no error, continue..
            errors = []
            # this is to check whether analysis completed or not..
            resp = self._poll_for_result(r.json()["key"])
            err = resp.get("error", None)
            if err:
                errors.append(err)
            logger.info(
                f"Fetching final report ({self.analyzer_name}, job_id: #{self.job_id})"
            )
            # if no error, we fetch the final report..
            result_resp = requests.get(f"{self.base_url}/get-result?name={fname}")
            if not result_resp.status_code == 200:
                e = resp.json()["error"]
                errors.append(e)
                raise AnalyzerRunException(", ".join(errors))

            return result_resp.json()
