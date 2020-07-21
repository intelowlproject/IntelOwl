import requests
import logging

from api_app.helpers import get_binary
from api_app.script_analyzers.classes import FileAnalyzer, DockerBasedAnalyzer
from api_app.exceptions import AnalyzerConfigurationException

logger = logging.getLogger(__name__)


class BoxJS(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "box-js"
    base_url: str = "http://boxjs:4003"
    url: str = f"{base_url}/boxjs"
    # http request polling max number of tries
    max_tries: int = 20
    # interval between http request polling (in secs)
    poll_distance: int = 10

    def run(self):
        # construct a valid filename into which thug will save the result
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        # get the file to send
        binary = get_binary(self.job_id)
        # construct arguments, For example this corresponds to,
        # box-js sample.js --output-dir=result --timeout 200 --no-kill --no-shell-error
        args = [
            f"@{fname}",
            "--output-dir=/tmp/boxjs",
            "--timeout 200",
            "--no-kill",
            "--no-shell-error",
            "--no-echo",
        ]

        # step #1: request new analysis
        logger.debug(f"Making request with arguments: {args} <- {self.__repr__()}")
        try:
            resp1 = requests.post(
                self.url, files={fname: binary}, data={"args": args,},
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
