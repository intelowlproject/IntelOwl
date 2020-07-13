import requests
import logging
from urllib.parse import urlparse

from api_app.script_analyzers.classes import ObservableAnalyzer, DockerBasedAnalyzer
from api_app.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class ThugUrl(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "Thug"
    base_url: str = "http://thug:4001"
    url: str = "http://thug:4001/thug"
    # http request polling max number of tries
    max_tries: int = 7
    # interval between http request polling (in seconds)
    poll_distance: int = 60

    def set_config(self, additional_config_params):
        self.args = self._thug_args_builder(additional_config_params)
        self.is_test = additional_config_params.get("test", False)

    @staticmethod
    def _thug_args_builder(config_params):
        user_agent = config_params.get("user_agent", "winxpie60")
        dom_events = config_params.get("dom_events", None)
        use_proxy = config_params.get("use_proxy", False)
        proxy = config_params.get("proxy", None)
        enable_awis = config_params.get("enable_awis", False)
        enable_img_proc = config_params.get("enable_image_processing_analysis", False)
        # make request arguments
        # analysis timeout is set to 5 minutes
        args = ["-T", "300", "-u", str(user_agent)]
        if dom_events:
            args.extend(["-e", str(dom_events)])
        if use_proxy and proxy:
            args.extend(["-p", str(proxy)])
        if enable_awis:
            args.append("--awis")
        if enable_img_proc:
            args.append("--image-processing")

        return args

    def run(self):
        if self.observable_classification == "url":
            tmp_dir = str(urlparse(self.observable_name).netloc)
        elif self.observable_classification == "domain":
            tmp_dir = self.observable_name
        else:
            raise AnalyzerRunException(
                f"Requested type: '{self.observable_classification}' is not supported'"
                f"Supported are: URL, Domain."
            )
        self.args.extend(["-n", "/tmp/thug/" + tmp_dir, self.observable_name])
        logger.debug(
            f"Making request with arguments: {self.args}"
            f" for analyzer: {self.analyzer_name}, job_id: #{self.job_id}."
        )
        # request new analysis
        r = requests.post(self.url, json={"args": self.args,})
        # handle cases in case of error
        if self._check_status_code(self.name, r):
            # if no error, continue..
            errors = []
            # this is to check whether analysis completed or not..
            key = r.json().get("key", None)
            if not key:
                if self.is_test:
                    # if this is a test, then just return here..
                    return {}
                # else raise exception
                raise AnalyzerRunException(
                    f"Unexpected Error. Please check {self.name} container's log files."
                )
            resp = self._poll_for_result(key)
            err = resp.get("error", None)
            if err:
                errors.append(err)
            logger.info(
                f"Fetching final report ({self.analyzer_name}, job_id: #{self.job_id})"
            )
            # if no error, we fetch the final report..
            result_resp = requests.get(f"{self.base_url}/get-result?name={tmp_dir}")
            if not result_resp.status_code == 200:
                e = resp.json()["error"]
                errors.append(e)
                raise AnalyzerRunException(", ".join(errors))

            return result_resp.json()
