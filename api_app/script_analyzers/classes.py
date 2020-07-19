import traceback
import time
import logging
import requests
import json
from abc import ABC, abstractmethod

from api_app.exceptions import (
    AnalyzerRunNotImplemented,
    AnalyzerRunException,
    AnalyzerConfigurationException,
)
from .utils import get_basic_report_template, set_report_and_cleanup

logger = logging.getLogger(__name__)


class BaseAnalyzerMixin(ABC):
    """
    Abstract Base class for Analyzers.
    Never inherit from this branch,
    always use either one of ObservableAnalyzer or FileAnalyzer classes.
    """

    __job_id: int
    analyzer_name: str

    @property
    def job_id(self):
        return self.__job_id

    @abstractmethod
    def before_run(self):
        """
        function called directly before run function.
        """

    @abstractmethod
    def run(self):
        # this should be overwritten in
        # child class
        raise AnalyzerRunNotImplemented(self.analyzer_name)

    @abstractmethod
    def after_run(self):
        """
        function called after run function.
        """

    def set_config(self, additional_config_params):
        """
        function to parse additional_config_params.
        verify params, API keys, etc.
        In most cases, this would be overwritten.
        """

    def start(self):
        """
        Entrypoint function to execute the analyzer.
        calls `before_run`, `run`, `after_run`
        in that order with exception handling.
        """
        self.before_run()
        try:
            self.report = get_basic_report_template(self.analyzer_name)
            result = self.run()
            self.report["report"] = result
        except (AnalyzerConfigurationException, AnalyzerRunException) as e:
            self._handle_analyzer_exception(e)
        except Exception as e:
            self._handle_base_exception(e)
        else:
            self.report["success"] = True

        # add process time
        self.report["process_time"] = time.time() - self.report["started_time"]
        set_report_and_cleanup(self.job_id, self.report)

        self.after_run()

        return self.report

    def _handle_analyzer_exception(self, err):
        error_message = (
            f"job_id:{self.job_id}, analyzer: '{self.analyzer_name}'."
            f" Analyzer error: '{err}'"
        )
        logger.error(error_message)
        self.report["errors"].append(error_message)
        self.report["success"] = False

    def _handle_base_exception(self, err):
        traceback.print_exc()
        error_message = (
            f"job_id:{self.job_id}, analyzer:'{self.analyzer_name}'."
            f" Unexpected error: '{err}'"
        )
        logger.exception(error_message)
        self.report["errors"].append(str(err))
        self.report["success"] = False

    def __init__(self, analyzer_name, job_id, additional_config_params):
        self.analyzer_name = analyzer_name
        self.__job_id = job_id
        self.set_config(additional_config_params)  # lgtm [py/init-calls-subclass]

    def __repr__(self):
        return f"({self.analyzer_name}, job_id: #{self.job_id})"


class ObservableAnalyzer(BaseAnalyzerMixin):
    """
    Abstract class for Observable Analyzers.
    Inherit from this branch when defining a IP, URL or domain analyzer.
    Need to overrwrite `set_config(self, additional_config_params)`
     and `run(self)` functions.
    """

    observable_name: str
    observable_classification: str

    def __init__(
        self,
        analyzer_name,
        job_id,
        obs_name,
        obs_classification,
        additional_config_params,
    ):
        self.observable_name = obs_name
        self.observable_classification = obs_classification
        super().__init__(analyzer_name, job_id, additional_config_params)

    def before_run(self):
        logger.info(
            "STARTED analyzer: {}, job_id: {}, observable: {}"
            "".format(self.analyzer_name, self.job_id, self.observable_name)
        )

    def after_run(self):
        logger.info(
            f"ENDED analyzer: {self.analyzer_name}, job_id: {self.job_id},"
            f"observable: {self.observable_name}"
        )


class FileAnalyzer(BaseAnalyzerMixin):
    """
    Abstract class for File Analyzers.
    Inherit from this branch when defining a file analyzer.
    Need to overrwrite `set_config(self, additional_config_params)`
     and `run(self)` functions.
    """

    md5: str
    filepath: str
    filename: str

    def __init__(
        self, analyzer_name, job_id, fpath, fname, md5, additional_config_params
    ):
        self.md5 = md5
        self.filepath = fpath
        self.filename = fname
        super().__init__(analyzer_name, job_id, additional_config_params)

    def before_run(self):
        logger.info(
            f"STARTED analyzer: {self.analyzer_name}, job_id: #{self.job_id}"
            f" ({self.filename}, md5: {self.md5})"
        )

    def after_run(self):
        logger.info(
            f"ENDED analyzer: {self.analyzer_name}, job_id: #{self.job_id},"
            f" ({self.filename}, md5: {self.md5})"
        )


class DockerBasedAnalyzer(ABC):
    """
    Abstract class for a docker based analyzer (integration).
    Inherit this branch along with either one of ObservableAnalyzer or FileAnalyzer
    when defining a docker based analyzer.
    See `peframe.py` for example.

    :param name: str
        The name of the analyzer service as defined in compose file
        and log directory
    :param max_tries: int
        maximum no. of tries when HTTP polling for result.
    :param poll_distance: int
        interval between HTTP polling.
    """

    name: str
    max_tries: int
    poll_distance: int

    @staticmethod
    def _raise_in_case_bad_request(name, resp):
        """
        Raises:
            :class: `AnalyzerRunException`, if bad status code or no key in response
        """
        # different error messages for different cases
        if resp.status_code == 404:
            raise AnalyzerConfigurationException(
                f"{name} docker container is not running."
            )
        if resp.status_code == 400:
            err = resp.json().get("error", "")
            raise AnalyzerRunException(err)
        if resp.status_code == 500:
            raise AnalyzerRunException(
                f"Internal Server Error in {name} docker container"
            )
        # check to make sure there was a valid key in response
        key = resp.json().get("key", None)
        if not key:
            raise AnalyzerRunException(
                "Unexpected Error. "
                f"Please check log files under /var/log/intel_owl/{name.lower()}/"
            )
        # just in case couldn't catch the error manually
        resp.raise_for_status()

        return True

    @staticmethod
    def _query_for_result(url, key):
        headers = {"Accept": "application/json"}
        resp = requests.get(f"{url}?key={key}", headers=headers)
        return resp.status_code, resp.json()

    def _poll_for_result(self, req_key):
        allowed_statuses = ("success", "reported_with_fails", "failed")
        got_result = False
        json_data = {}
        for chance in range(self.max_tries):
            time.sleep(self.poll_distance)
            logger.info(
                f"Result Polling. Try #{chance+1}. Starting the query..."
                f"<-- {self.__repr__()}"
            )
            try:
                status_code, json_data = self._query_for_result(self.url, req_key)
            except (requests.RequestException, json.JSONDecodeError) as e:
                raise AnalyzerRunException(e)
            analysis_status = json_data.get("status", None)
            if analysis_status in allowed_statuses:
                got_result = True
                break
            else:
                logger.info(
                    f"Poll number #{chance+1}, status: 'running' <-- {self.__repr__()}"
                )

        if not got_result:
            raise AnalyzerRunException("max polls tried without getting any result.")
        return json_data

    def _get_result_from_a_dir(self, key, dir_file_name):
        """
        In case the analyzer does not output result to stdout,
        we define a `/get-result` route to fetch the final result
        from a given directory/file.

        :param key: str
            Unique key for the particular analysis
        :param name: str
            File/directory name to read result from

        :raises AnalyzerRunException:
            analysis was requested but get-result failed

        :returns: dict()
            Final Report
        """
        errors = []
        # step #1: this is to check whether analysis completed or not..
        poll_resp = self._poll_for_result(key)
        err = poll_resp.get("error", None)
        if err:
            # this may return error, but we can still try to fetch report
            errors.append(err)

        # step #2: try to fetch the final report..
        logger.info(f"Fetching final report <-- {self.__repr__()}")
        result_resp = requests.get(f"{self.base_url}/get-result?name={dir_file_name}")
        if not result_resp.status_code == 200:
            e = result_resp.json().get("error", "")
            errors.append(e)
            raise AnalyzerRunException(", ".join(errors))

        return result_resp.json()
