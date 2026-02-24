# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import time
from abc import ABCMeta
from pathlib import PosixPath
from typing import Dict, Tuple

import requests
from django.conf import settings

from api_app.decorators import classproperty
from certego_saas.apps.user.models import User

from ..choices import Classification, PythonModuleBasePaths
from ..classes import Plugin
from ..data_model_manager.enums import DataModelEvaluations
from ..models import PythonConfig
from .constants import HashChoices, TypeChoices
from .exceptions import AnalyzerConfigurationException, AnalyzerRunException
from .models import AnalyzerConfig, AnalyzerReport

logger = logging.getLogger(__name__)


class BaseAnalyzerMixin(Plugin, metaclass=ABCMeta):
    """
    Abstract Base class for Analyzers.
    Never inherit from this branch,
    always use either one of ObservableAnalyzer or FileAnalyzer classes.
    """

    HashChoices = HashChoices
    TypeChoices = TypeChoices
    EVALUATIONS = DataModelEvaluations

    def _do_create_data_model(self) -> bool:
        if self.report.job.analyzable.classification == Classification.GENERIC.value:
            return False
        if (
            not self._config.mapping_data_model
            and self.__class__._create_data_model_mtm
            == BaseAnalyzerMixin._create_data_model_mtm
            and self.__class__._update_data_model
            == BaseAnalyzerMixin._update_data_model
        ):
            return False
        return True

    def _create_data_model_mtm(self):
        return {}

    def _update_data_model(self, data_model) -> None:
        mtm = self._create_data_model_mtm()
        for field_name, value in mtm.items():
            field = getattr(data_model, field_name)
            field.add(*value)

    def create_data_model(self):
        self.report: AnalyzerReport
        if self._do_create_data_model():
            data_model = self.report.create_data_model()
            if data_model:
                self._update_data_model(data_model)
                data_model.save()
            return data_model
        return None

    @classproperty
    def config_exception(cls):
        """Returns the AnalyzerConfigurationException class."""
        return AnalyzerConfigurationException

    @property
    def analyzer_name(self) -> str:
        """Returns the name of the analyzer."""
        return self._config.name

    @classproperty
    def report_model(cls):
        """Returns the AnalyzerReport model."""
        return AnalyzerReport

    @classproperty
    def config_model(cls):
        """Returns the AnalyzerConfig model."""
        return AnalyzerConfig

    def get_exceptions_to_catch(self):
        """
        Returns additional exceptions to catch when running *start* fn
        """
        return (
            AnalyzerConfigurationException,
            AnalyzerRunException,
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
                result[key] = self._validate_result(
                    values, level=level + 1, max_recursion=max_recursion
                )
        elif isinstance(result, list):
            for i, _ in enumerate(result):
                result[i] = self._validate_result(
                    result[i], level=level + 1, max_recursion=max_recursion
                )
        elif isinstance(result, str):
            return result.replace("\u0000", "")
        elif isinstance(result, int) and result > 9223372036854775807:  # max int 8bytes
            result = 9223372036854775807
        return result

    def after_run_success(self, content):
        """
        Handles actions after a successful run.

        Args:
            content (any): The content to process after a successful run.
        """
        super().after_run_success(self._validate_result(content, max_recursion=15))
        try:
            self.create_data_model()
        except Exception as e:
            logger.exception(e)
            self._job.errors.append(
                f"Data model creation failed for {self._config.name}"
            )


class ObservableAnalyzer(BaseAnalyzerMixin, metaclass=ABCMeta):
    """
    Abstract class for Observable Analyzers.
    Inherit from this branch when defining a IP, URL or domain analyzer.
    Need to overrwrite `set_params(self, params)`
     and `run(self)` functions.
    """

    observable_name: str
    observable_classification: str

    def __init__(
        self,
        config: PythonConfig,
        **kwargs,
    ):
        super().__init__(config, **kwargs)

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self._config: AnalyzerConfig
        if self._job.is_sample and self._config.run_hash:
            self.observable_classification = Classification.HASH
            # check which kind of hash the analyzer needs
            run_hash_type = self._config.run_hash_type
            if run_hash_type == HashChoices.SHA256:
                self.observable_name = self._job.analyzable.sha256
            else:
                self.observable_name = self._job.analyzable.md5
        else:
            self.observable_name = self._job.analyzable.name
            self.observable_classification = self._job.analyzable.classification

    @classproperty
    def python_base_path(cls):
        return PythonModuleBasePaths.ObservableAnalyzer.value

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

    def __init__(
        self,
        config: PythonConfig,
        **kwargs,
    ):
        super().__init__(config, **kwargs)

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.md5 = self._job.analyzable.md5
        self.filename = self._job.analyzable.name
        # this is updated in the filepath property, like a cache decorator.
        # if the filepath is requested, it means that the analyzer downloads...
        # ...the file from AWS because it requires a path and it needs to be deleted
        self.__filepath = None
        self.file_mimetype = self._job.analyzable.mimetype

    @classproperty
    def python_base_path(cls) -> PosixPath:
        return PythonModuleBasePaths[FileAnalyzer.__name__].value

    def read_file_bytes(self) -> bytes:
        return self._job.analyzable.read()

    @property
    def filepath(self) -> str:
        """Returns the file path, retrieving the file from storage if necessary.

        Returns:
            str: The file path.
        """
        if not self.__filepath:
            self.__filepath = self._job.analyzable.file.storage.retrieve(
                file=self._job.analyzable.file, analyzer=self.analyzer_name
            )
        return self.__filepath

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
        if not settings.LOCAL_STORAGE and self.filepath is not None:
            import os

            try:
                os.remove(self.filepath)
            except OSError:
                logger.warning(f"Filepath {self.filepath} does not exists")

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
    key_not_found_max_retries: int = 10

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

    def __polling(self, req_key: str, chance: int, re_poll_try: int = 0):
        try:
            status_code, json_data = self.__query_for_result(self.url, req_key)
        except (requests.RequestException, json.JSONDecodeError) as e:
            raise AnalyzerRunException(e)
        if status_code == 404:
            # This happens when they key does not exist.
            # This is possible in case IntelOwl is deployed as a Swarm.
            # The previous POST request that created the analysis ...
            # ...could have been sent to a different container in another machine.
            # so we need to try again and find the server with the key
            logger.info(
                "Polling again because received a 404."
                f" Try #{chance + 1}. Re-Poll try {re_poll_try}. Starting the query..."
                f"<-- {self.__repr__()}"
            )
            if self.key_not_found_max_retries == re_poll_try:
                raise AnalyzerRunException(
                    f"not found key {req_key} in any server after maximum retries"
                )
            return self.__polling(req_key, chance, re_poll_try=re_poll_try + 1)
        else:
            status = json_data.get("status", None)
            if status and status == self._job.STATUSES.RUNNING.value:
                logger.info(
                    f"Poll number #{chance + 1}, "
                    f"status: 'running' <-- {self.__repr__()}"
                )
            else:
                return True, json_data
        return False, json_data

    def __poll_for_result(self, req_key: str) -> dict:
        got_result = False
        json_data = {}
        for chance in range(self.max_tries):
            time.sleep(self.poll_distance)
            logger.info(
                f"Result Polling. Try #{chance + 1}. Starting the query..."
                f"<-- {self.__repr__()}"
            )
            got_result, json_data = self.__polling(req_key, chance)
            if got_result:
                break

        if not got_result:
            raise AnalyzerRunException("max polls tried without getting any result.")
        return json_data

    def _raise_container_not_running(self) -> None:
        raise AnalyzerConfigurationException(
            f"{self.name} docker container is not running.\n"
            "You have to enable it using the appropriate "
            "parameter when executing ./start."
        )

    def _docker_run(
        self,
        req_data: dict,
        req_files: dict = None,
        analyzer_name: str = None,
        avoid_polling: bool = False,
    ) -> dict:
        """
        Helper function that takes of care of requesting new analysis,
        reading response, polling for result and exception handling for a
        docker based analyzer.

        Args:
            req_data (Dict): Dict of request JSON.
            req_files (Dict, optional): Dict of files to send. Defaults to None.
            analyzer_name: optional, could be used for edge cases

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
        # Modified to support synchronous analyzers that return results directly in the initial response, avoiding unnecessary polling.
        if avoid_polling:
            report = resp1.json().get("report", None)
            err = resp1.json().get("error", None)
        else:
            if not self.__raise_in_case_bad_request(self.name, resp1):
                raise AssertionError

            # step #3: if no error, continue and try to fetch result
            key = resp1.json().get("key")
            final_resp = self.__poll_for_result(key)
            err = final_resp.get("error", None)
            report = final_resp.get("report", None)

        # APKiD provides empty result in case it does not support the binary type
        if not report and (analyzer_name != "APKiD"):
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

    def health_check(self, user: User = None) -> bool:
        """
        basic health check: if instance is up or not (timeout - 10s)
        """
        try:
            requests.head(self.url, timeout=10)
        except requests.exceptions.RequestException:
            health_status = False
        else:
            health_status = True

        return health_status
