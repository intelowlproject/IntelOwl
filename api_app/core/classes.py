# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import traceback
import typing
from abc import ABCMeta, abstractmethod

from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.utils import timezone
from django.utils.functional import cached_property

from api_app.models import Job

from .models import AbstractConfig, AbstractReport

logger = logging.getLogger(__name__)


class Plugin(metaclass=ABCMeta):
    """
    Abstract Base class for plugins.
    For internal use only.
    """

    def __init__(
        self,
        config: AbstractConfig,
        job_id: int,
        runtime_configuration: dict,
        task_id: int,
        **kwargs,
    ):

        self._config = config
        self.job_id = job_id
        self.runtime_configuration = runtime_configuration
        self.task_id = task_id

        self.kwargs = kwargs
        # some post init processing
        self.__post__init__()  # lgtm [py/init-calls-subclass]

    @classmethod
    def all_subclasses(cls):
        classes = cls.__subclasses__()
        return [
            class_ for class_ in classes if not class_.__name__.startswith("MockUp")
        ]

    def __post__init__(self) -> None:
        """
        Hook for post `__init__` processing.
        Always call `super().__post__init__()` if overwritten in subclass.
        """
        # init report
        self.report = self.init_report_object()
        # monkeypatch if in test suite
        if settings.STAGE_CI:
            self._monkeypatch()

    @cached_property
    def _job(self) -> "Job":
        from api_app.models import Job

        return Job.objects.get(pk=self.job_id)

    def __repr__(self):
        return f"({self.__class__.__name__}, job: #{self.job_id})"

    @cached_property
    def _secrets(self) -> dict:
        return self._config.read_secrets(user=self._job.user)

    @cached_property
    def _params(self) -> dict:
        default_params = self._config.read_params(user=self._job.user)
        # overwrite default with runtime
        return {**default_params, **self.runtime_configuration}

    def config(self):
        for param, value in self._params.items():
            setattr(self, param, value)
        for secret, value in self._secrets.items():
            setattr(self, f"_{secret}", value)

    @abstractmethod
    def before_run(self, *args, **kwargs):
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

    @classmethod
    @property
    @abstractmethod
    def report_model(cls) -> typing.Type[AbstractReport]:
        """
        Returns Model to be used for *init_report_object*
        """
        raise NotImplementedError()

    @classmethod
    @property
    @abstractmethod
    def config_model(cls) -> typing.Type[AbstractConfig]:
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
            config=self._config,
            defaults={
                "report": {},
                "errors": [],
                "status": AbstractReport.Status.PENDING.value,
                "start_time": timezone.now(),
                "end_time": timezone.now(),
                "task_id": self.task_id,
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
        self.config()
        try:
            self.before_run()
            _result = self.run()
            self.report.report = _result
        except (*self.get_exceptions_to_catch(), SoftTimeLimitExceeded) as e:
            self._handle_exception(e)
            if settings.STAGE_CI:
                raise e
        except Exception as e:
            self._handle_base_exception(e)
            if settings.STAGE_CI:
                raise e
        else:
            self.report.status = self.report.Status.SUCCESS.value
        finally:
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

    @classmethod
    @property
    def python_module(cls) -> str:
        module = cls.__module__.split(".")[-1]
        return f"{module}.{cls.__name__}"
