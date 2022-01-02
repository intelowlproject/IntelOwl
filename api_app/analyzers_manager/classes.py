# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import time
from abc import ABCMeta
from typing import Tuple

import requests
from django.conf import settings

from api_app.core.classes import Plugin
from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException
from tests.mock_utils import (
    if_mock_connections,
    mocked_docker_analyzer_get,
    mocked_docker_analyzer_post,
    patch,
)

from .constants import HashChoices, ObservableTypes, TypeChoices
from .models import AnalyzerReport

logger = logging.getLogger(__name__)


class BaseAnalyzerMixin(Plugin):
    """
    Abstract Base class for Analyzers.
    Never inherit from this branch,
    always use either one of ObservableAnalyzer or FileAnalyzer classes.
    """

    HashChoices = HashChoices
    ObservableTypes = ObservableTypes
    TypeChoices = TypeChoices

    @property
    def analyzer_name(self) -> str:
        return self._config.name

    @property
    def report_model(self):
        return AnalyzerReport

    def get_exceptions_to_catch(self):
        """
        Returns additional exceptions to catch when running *start* fn
        """
        return (
            AnalyzerConfigurationException,
            AnalyzerRunException,
        )

    def get_error_message(self, err, is_base_err=False):
        """
        Returns error message for
        *_handle_analyzer_exception* and *_handle_base_exception* fn
        """
        return (
            f"{self.__repr__()}."
            f" {'Unexpected error' if is_base_err else 'Analyzer error'}: '{err}'"
        )

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

    def before_run(self):
        self.report.update_status(status=self.report.Status.RUNNING)

    def after_run(self):
        self.report.report = self._validate_result(self.report.report)

    def __repr__(self):
        return f"({self.analyzer_name}, job_id: #{self.job_id})"


class ObservableAnalyzer(BaseAnalyzerMixin, metaclass=ABCMeta):
    """
    Abstract class for Observable Analyzers.
    Inherit from this branch when defining a IP, URL or domain analyzer.
    Need to overrwrite `set_params(self, params)`
     and `run(self)` functions.
    """

    observable_name: str
    observable_classification: str

    def __post__init__(self):
        # check if we should run the hash instead of the binary
        if self._job.is_sample and self._config.run_hash:
            self.observable_classification = ObservableTypes.HASH
            # check which kind of hash the analyzer needs
            run_hash_type = self._config.run_hash_type
            if run_hash_type == HashChoices.SHA256:
                self.observable_name = self._job.sha256
            else:
                self.observable_name = self._job.md5
        else:
            self.observable_name = self._job.observable_name
            self.observable_classification = self._job.observable_classification
        return super(ObservableAnalyzer, self).__post__init__()

    def before_run(self):
        super().before_run()
        logger.info(
            f"STARTED analyzer: {self.__repr__()} -> "
            f"Observable: {self.observable_name}."
        )

    def after_run(self):
        super().after_run()
        logger.info(
            f"FINISHED analyzer: {self.__repr__()} -> "
            f"Observable: {self.observable_name}."
        )


class FileAnalyzer(BaseAnalyzerMixin, metaclass=ABCMeta):
    """
    Abstract class for File Analyzers.
    Inherit from this branch when defining a file analyzer.
    Need to overrwrite `set_params(self, params)`
     and `run(self)` functions.
    """

    md5: str
    filename: str
    file_mimetype: str

    def read_file_bytes(self) -> bytes:
        return self._job.file.read()

    @property
    def filepath(self) -> str:
        if not self.__filepath:
            self.__filepath = self._job.file.storage.retrieve(
                file=self._job.file, analyzer=self.analyzer_name
            )
        return self.__filepath

    def __post__init__(self):
        self.md5 = self._job.md5
        self.filename = self._job.file_name
        # this is updated in the filepath property, like a cache decorator.
        # if the filepath is requested, it means that the analyzer downloads...
        # ...the file from AWS because it requires a path and it needs to be deleted
        self.__filepath = None
        self.file_mimetype = self._job.file_mimetype
        return super(FileAnalyzer, self).__post__init__()

    def before_run(self):
        super().before_run()
        logger.info(
            f"STARTED analyzer: {self.__repr__()} -> "
            f"File: ({self.filename}, md5: {self.md5})"
        )

    def after_run(self):
        super().after_run()
        # We delete the file only if we have single copy for analyzer
        # and the file has been saved locally.
        # Otherwise we would remove the single file that we have on the server
        if not settings.LOCAL_STORAGE and self.__filepath is not None:
            import os

            os.remove(self.filepath)

        logger.info(
            f"FINISHED analyzer: {self.__repr__()} -> "
            f"File: ({self.filename}, md5: {self.md5})"
        )


class DockerBasedAnalyzer(BaseAnalyzerMixin, metaclass=ABCMeta):
    """
    Abstract class for a docker based analyzer (integration).
    Inherit this branch along with either
    one of ``ObservableAnalyzer`` or ``FileAnalyzer``
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
    def __raise_in_case_bad_request(name, resp, params_to_check=None) -> bool:
        """
        Raises:
            :class: `AnalyzerRunException`, if bad status code or no key in response
        """
        if params_to_check is None:
            params_to_check = ["key"]
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
        # check to make sure there was a valid params in response
        for param in params_to_check:
            param_value = resp.json().get(param, None)
            if not param_value:
                raise AnalyzerRunException(
                    "Unexpected Error. "
                    f"Please check log files under /var/log/intel_owl/{name.lower()}/"
                )
        # just in case couldn't catch the error manually
        resp.raise_for_status()

        return True

    @staticmethod
    def __query_for_result(url: str, key: str) -> Tuple[int, dict]:
        headers = {"Accept": "application/json"}
        resp = requests.get(f"{url}?key={key}", headers=headers)
        return resp.status_code, resp.json()

    def __poll_for_result(self, req_key: str) -> dict:
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

    def _raise_container_not_running(self) -> None:
        raise AnalyzerConfigurationException(
            f"{self.name} docker container is not running.\n"
            f"You have to enable it using the appropriate "
            f"parameter when executing start.py."
        )

    def _docker_run(self, req_data: dict, req_files: dict = None) -> dict:
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

        # step #1: request new analysis
        req_data = {**req_data, "force_unique_key": True}
        args = req_data.get("args", [])
        logger.debug(f"Making request with arguments: {args} <- {self.__repr__()}")
        try:
            if req_files:
                form_data = {"request_json": json.dumps(req_data)}
                resp1 = requests.post(self.url, files=req_files, data=form_data)
            else:
                resp1 = requests.post(self.url, json=req_data)
        except requests.exceptions.ConnectionError:
            self._raise_container_not_running()

        # step #2: raise AnalyzerRunException in case of error
        if not self.__raise_in_case_bad_request(self.name, resp1):
            raise AssertionError

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
            # because report may also be a str only. Example: clamav.
            pass

        return report

    def _docker_get(self):
        """
        Raises:
            AnalyzerConfigurationException: In case docker service is not running
            AnalyzerRunException: Any other error

        Returns:
            Response: Response object of request
        """

        # step #1: request new analysis
        try:
            resp = requests.get(url=self.url)
        except requests.exceptions.ConnectionError:
            self._raise_container_not_running()

        # step #2: raise AnalyzerRunException in case of error
        if not self.__raise_in_case_bad_request(self.name, resp, params_to_check=[]):
            raise AssertionError
        return resp

    def _monkeypatch(self, patches: list = None):
        """
        Here, `_monkeypatch` is an instance method and not a class method.
        This is because when defined with `@classmethod`, we were getting the error
        ```
        '_patch' object has no attribute 'is_local'
        ```
        whenever multiple analyzers with same parent class were being called.
        """
        if patches is None:
            patches = []
        # no need to sleep during tests
        self.poll_distance = 0
        patches.append(
            if_mock_connections(
                patch(
                    "requests.get",
                    side_effect=mocked_docker_analyzer_get,
                ),
                patch(
                    "requests.post",
                    side_effect=mocked_docker_analyzer_post,
                ),
            )
        )
        for mock_fn in patches:
            self.start = mock_fn(self.start)

    @classmethod
    def health_check(cls) -> bool:
        """
        basic health check: if instance is up or not (timeout - 10s)
        """
        health_status = False

        try:
            requests.head(cls.url, timeout=10)
            health_status = True
        except requests.exceptions.ConnectionError:
            # status=False, so pass
            pass
        except requests.exceptions.Timeout:
            # status=False, so pass
            pass

        return health_status
