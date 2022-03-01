# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import traceback
from abc import ABCMeta, abstractmethod

from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.utils import timezone
from django.utils.functional import cached_property

from api_app.models import Job

from .dataclasses import AbstractConfig
from .models import AbstractReport

logger = logging.getLogger(__name__)


class Plugin(metaclass=ABCMeta):
    """
    Abstract Base class for plugins.
    For internal use only.
    """

    _config: AbstractConfig
    job_id: int
    report_defaults: dict
    kwargs: dict
    report: AbstractReport

    @cached_property
    def _job(self) -> Job:
        return Job.objects.get(pk=self.job_id)

    @cached_property
    def _secrets(self) -> dict:
        return self._config._read_secrets()

    @property
    def _params(self) -> dict:
        default_params = self._config.param_values
        runtime_params = self.report_defaults["runtime_configuration"]
        # overwrite default with runtime
        return {**default_params, **runtime_params}

    def set_params(self, params: dict):
        """
        Method which receives the parsed `config["params"]` dict.
        This is called inside `__post__init__`.
        """

    @abstractmethod
    def before_run(self):
        """
        function called directly before run function.
        """
        raise NotImplementedError()

    @abstractmethod
    def run(self) -> dict:
        """
        Called from *start* fn and wrapped in a try-catch block.
        Should be overwritten in child class
        :returns report
        """
        raise NotImplementedError()

    @abstractmethod
    def after_run(self):
        """
        function called after run function.
        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def report_model(self):
        """
        Returns Model to be used for *init_report_object*
        """
        raise NotImplementedError()

    def init_report_object(self):
        """
        Returns report object set in *__post__init__* fn
        """
        # unique constraint ensures only one report is possible
        # update case: recurring plugin run
        _report, _ = self.report_model.objects.update_or_create(
            job_id=self.job_id,
            name=self._config.name,
            defaults={
                "report": {},
                "errors": [],
                "status": AbstractReport.Status.PENDING,
                "start_time": timezone.now(),
                "end_time": timezone.now(),
                **self.report_defaults,
            },
        )
        return _report

    @abstractmethod
    def get_exceptions_to_catch(self) -> list:
        """
        Returns list of `Exception`'s to handle.
        """
        raise NotImplementedError()

    def get_error_message(self, exc, is_base_err=False):
        return f" {'[Unexpected error]' if is_base_err else '[Error]'}: '{exc}'"

    def start(self, *args, **kwargs) -> AbstractReport:
        """
        Entrypoint function to execute the plugin.
        calls `before_run`, `run`, `after_run`
        in that order with exception handling.
        """
        try:
            self.before_run()
            _result = self.run()
            self.report.report = _result
        except (*self.get_exceptions_to_catch(), SoftTimeLimitExceeded) as e:
            self._handle_exception(e)
        except Exception as e:
            self._handle_base_exception(e)
        else:
            self.report.status = self.report.Status.SUCCESS

        # add end time of process
        self.report.end_time = timezone.now()

        self.after_run()
        self.report.save()

        return self.report

    def _handle_exception(self, exc) -> None:
        error_message = self.get_error_message(exc)
        logger.error(error_message)
        self.report.errors.append(str(exc))
        self.report.status = self.report.Status.FAILED

    def _handle_base_exception(self, exc) -> None:
        traceback.print_exc()
        error_message = self.get_error_message(exc, is_base_err=True)
        logger.exception(error_message)
        self.report.errors.append(str(exc))
        self.report.status = self.report.Status.FAILED

    @classmethod
    def _monkeypatch(cls, patches: list = None) -> None:
        """
        Hook to monkey-patch class for testing purposes.
        """
        if patches is None:
            patches = []
        for mock_fn in patches:
            cls.start = mock_fn(cls.start)

    def __post__init__(self) -> None:
        """
        Hook for post `__init__` processing.
        Always call `super().__post__init__()` if overwritten in subclass.
        """
        # init report
        self.report = self.init_report_object()
        # set params
        self.set_params(self._params)
        # monkeypatch if in test suite
        if settings.STAGE_CI:
            self._monkeypatch()

    def __init__(
        self,
        config: AbstractConfig,
        job_id: int,
        report_defaults: dict = None,
        **kwargs,
    ):
        self._config = config
        self.job_id = job_id
        self.report_defaults = report_defaults if report_defaults is not None else {}
        self.kwargs = kwargs
        # some post init processing
        self.__post__init__()  # lgtm [py/init-calls-subclass]
