import requests
import logging

from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer, DockerBasedAnalyzer
from ..observable_analyzers.thug_url import ThugUrl
from api_app.exceptions import AnalyzerConfigurationException

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
        # construct a valid filename into which thug will save the result
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        # get the file to send
        binary = get_binary(self.job_id)
        # append final arguments,
        # -n -> output directory
        # -l -> the local file to analyze
        self.args.extend(["-n", "/tmp/thug/" + fname, "-l", f"@{fname}"])

        # step #1: request new analysis
        logger.debug(f"Making request with arguments: {self.args} <- {repr(self)}")
        try:
            resp1 = requests.post(
                self.url, files={fname: binary}, data={"args": self.args,},
            )
        except requests.exceptions.ConnectionError:
            raise AnalyzerConfigurationException(
                f"{self.name} docker container is not running."
            )

        # step #2: raise AnalyzerRunException in case of error
        assert self._raise_in_case_bad_request(self.name, resp1)

        # step #3: if no error, continue try to fetch result
        key = resp1.json().get("key", None)
        return self._get_result_from_a_dir(key, fname)
