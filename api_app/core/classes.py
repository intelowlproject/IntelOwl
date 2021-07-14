# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import traceback
import logging
from abc import ABCMeta, abstractmethod

from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone
from django.utils.functional import cached_property
from django.conf import settings

from api_app.models import Job
from .models import AbstractReport
from .serializers import AbstractConfigSerializer

logger = logging.getLogger(__name__)


class Plugin(metaclass=ABCMeta):
    """
    Abstract Base class for plugins.
    For internal use only.
    """

    _config_dict: dict
    job_id: int
    kwargs: dict
    report: AbstractReport

    @cached_property
    def _job(self) -> Job:
        return Job.objects.get(pk=self.job_id)

    @cached_property
    def _serializer(self) -> AbstractConfigSerializer:
        klass = self.get_serializer_class()
        serializer = klass(data=self._config_dict)
        serializer.is_valid(raise_exception=True)
        return serializer

    @cached_property
    def _secrets(self) -> dict:
        return self._serializer._read_secrets()

    @cached_property
    def _params(self) -> dict:
        return self._serializer.data["config"]

    def set_params(self, params: dict):
        """
        method which receives the parse config["config"] dict.
        This is called inside `start` and serves as a post `__init__` hook.
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

    @abstractmethod
    def init_report_object(self) -> AbstractReport:
        """
        Returns: instance of a subclass of ``AbstractReport``.
        Called inside `__init__`.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_exceptions_to_catch(self) -> list:
        """
        Returns list of `Exception`'s to handle.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_serializer_class(self) -> AbstractConfigSerializer:
        """
        Returns serializer class
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
            self.report.status = self.report.Statuses.SUCCESS.name

        # add end time of process
        self.report.end_time = timezone.now()

        self.after_run()
        self.report.save()

        return self.report

    def _handle_exception(self, exc) -> None:
        error_message = self.get_error_message(exc)
        logger.error(error_message)
        self.report.errors.append(str(exc))
        self.report.status = self.report.Statuses.FAILED.name

    def _handle_base_exception(self, exc) -> None:
        traceback.print_exc()
        error_message = self.get_error_message(exc, is_base_err=True)
        logger.exception(error_message)
        self.report.errors.append(str(exc))
        self.report.status = self.report.Statuses.FAILED.name

    @classmethod
    def _monkeypatch(cls, patches: list = []) -> None:
        """
        Hook to monkey-patch class for testing purposes.
        """
        for mock_fn in patches:
            cls.start = mock_fn(cls.start)

    def __post__init__(self) -> None:
        """
        Hook for post `__init__` processsing.
        Always call `super().__post__init__()` if overwritten in subclass.
        """
        # init report
        self.report = self.init_report_object()
        # set params
        self.set_params(self._params)
        # monkeypatch if in test suite
        if settings.TEST_MODE:
            self._monkeypatch()

    def __init__(self, config_dict: dict, job_id: int, **kwargs):
        self._config_dict = config_dict
        self.job_id = job_id
        self.kwargs = kwargs
        # some post init processing
        self.__post__init__()
