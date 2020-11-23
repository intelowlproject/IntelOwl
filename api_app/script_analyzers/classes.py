import traceback
import time
import logging
import requests
import json
from abc import ABCMeta, abstractmethod

from api_app.exceptions import (
    AnalyzerRunNotImplemented,
    AnalyzerRunException,
    AnalyzerConfigurationException,
)
from .utils import get_basic_report_template

logger = logging.getLogger(__name__)


class BaseAnalyzerMixin(metaclass=ABCMeta):
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
        """
        Called from *start* fn and wrapped in a try-catch block.
        Should be overwritten in child class
        :returns report: JSON
        """
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

    def _validate_result(self, result, level=0, max_recursion=190):
        """
        function to validate result, allowing to store inside postgres without errors.

        If the character \u0000 is present in the string, postgres will throw an error

        If an integer is bigger than max_int,
        Mongodb is not capable to store and will throw an error.

        If we have more than 200 recursion levels, every encoding
        will throw a maximum_nested_object exception
        """
        if level == max_recursion:
            logger.info(
                f"We have reached max_recursion {max_recursion} level. "
                f"The following object will be pruned {result} "
            )
            return None
        if isinstance(result, dict):
            for key, values in result.items():
                result[key] = self._validate_result(values, level=level + 1)
        elif isinstance(result, list):
            for i, _ in enumerate(result):
                result[i] = self._validate_result(result[i], level=level + 1)
        elif isinstance(result, str):
            return result.replace("\u0000", "")
        elif isinstance(result, int) and result > 9223372036854775807:  # max int 8bytes
            result = 9223372036854775807
        return result

    def start(self):
        """
        Entrypoint function to execute the analyzer.
        calls `before_run`, `run`, `after_run`
        in that order with exception handling.
        """
        try:
            self.before_run()
            self.report = get_basic_report_template(self.analyzer_name)
            result = self.run()
            result = self._validate_result(result)
            self.report["report"] = result
        except (AnalyzerConfigurationException, AnalyzerRunException) as e:
            self._handle_analyzer_exception(e)
        except Exception as e:
            self._handle_base_exception(e)
        else:
            self.report["success"] = True

        # add process time
        self.report["process_time"] = time.time() - self.report["started_time"]

        self.after_run()

        return self.report

    def _handle_analyzer_exception(self, err):
        error_message = (
            f"job_id:{self.job_id}, analyzer: '{self.analyzer_name}'."
            f" Analyzer error: '{err}'"
        )
        logger.error(error_message)
        self.report["errors"].append(str(err))
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
            f"STARTED analyzer: {self.__repr__()} -> "
            f"Observable: {self.observable_name}."
        )

    def after_run(self):
        logger.info(
            f"FINISHED analyzer: {self.__repr__()} -> "
            f"Observable: {self.observable_name}."
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
            f"STARTED analyzer: {self.__repr__()} -> "
            f"File: ({self.filename}, md5: {self.md5})"
        )

    def after_run(self):
        logger.info(
            f"FINISHED analyzer: {self.__repr__()} -> "
            f"File: ({self.filename}, md5: {self.md5})"
        )


class DockerBasedAnalyzer(metaclass=ABCMeta):
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
    url: str
    max_tries: int
    poll_distance: int

    @staticmethod
    def __raise_in_case_bad_request(name, resp):
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
    def __query_for_result(url, key):
        headers = {"Accept": "application/json"}
        resp = requests.get(f"{url}?key={key}", headers=headers)
        return resp.status_code, resp.json()

    def __poll_for_result(self, req_key):
        got_result = False
        json_data = {}
        for chance in range(self.max_tries):
            time.sleep(self.poll_distance)
            logger.info(
                f"Result Polling. Try #{chance + 1}. Starting the query..."
                f"<-- {self.__repr__()}"
            )
            try:
                status_code, json_data = self.__query_for_result(self.url, req_key)
            except (requests.RequestException, json.JSONDecodeError) as e:
                raise AnalyzerRunException(e)
            status = json_data.get("status", None)
            if status and status == "running":
                logger.info(
                    f"Poll number #{chance + 1}, "
                    f"status: 'running' <-- {self.__repr__()}"
                )
            else:
                got_result = True
                break

        if not got_result:
            raise AnalyzerRunException("max polls tried without getting any result.")
        return json_data

    def _docker_run(self, req_data, req_files=None):
        """
        Helper function that takes of care of requesting new analysis,
        reading response, polling for result and exception handling for a
        docker based analyzer.

        Args:
            req_data (Dict): Dict of request JSON.
            req_files (Dict, optional): Dict of files to send. Defaults to None.

        Raises:
            AnalyzerConfigurationException: In case docker service is not running
            AnalyzerRunException: Any other error

        Returns:
            Dict: Final analysis results
        """

        # handle in case this is a test
        if hasattr(self, "is_test") and getattr(self, "is_test"):
            # only happens in case of testing
            self.report["success"] = True
            return {}

        # step #1: request new analysis
        args = req_data.get("args", [])
        logger.debug(f"Making request with arguments: {args} <- {self.__repr__()}")
        try:
            if req_files:
                form_data = {"request_json": json.dumps(req_data)}
                resp1 = requests.post(self.url, files=req_files, data=form_data)
            else:
                resp1 = requests.post(self.url, json=req_data)
        except requests.exceptions.ConnectionError:
            raise AnalyzerConfigurationException(
                f"{self.name} docker container is not running.\n"
                f"You have to enable it in the .env file before starting IntelOwl."
            )

        # step #2: raise AnalyzerRunException in case of error
        assert self.__raise_in_case_bad_request(self.name, resp1)

        # step #3: if no error, continue and try to fetch result
        key = resp1.json().get("key")
        final_resp = self.__poll_for_result(key)
        err = final_resp.get("error", None)
        report = final_resp.get("report", None)

        if not report:
            raise AnalyzerRunException(f"Report is empty. Reason: {err}")

        if isinstance(report, dict):
            return report

        try:
            report = json.loads(report)
        except json.JSONDecodeError:
            raise AnalyzerRunException(str(err))

        return report
