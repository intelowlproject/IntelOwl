import logging
import traceback
import typing
from abc import ABCMeta, abstractmethod
from pathlib import PosixPath

from billiard.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.utils import timezone
from django.utils.functional import cached_property

from api_app.models import AbstractReport, Job, PythonConfig, PythonModule

logger = logging.getLogger(__name__)


class Plugin(metaclass=ABCMeta):
    """
    Abstract Base class for plugins.
    For internal use only.
    """

    def __init__(
        self,
        config: PythonConfig,
        job_id: int,
        runtime_configuration: dict,
        task_id: str,
        **kwargs,
    ):
        self._config = config
        self.job_id = job_id
        self.runtime_configuration = runtime_configuration
        self.task_id = task_id

        self.kwargs = kwargs
        # some post init processing
        self.report: AbstractReport = self._config.generate_empty_report(
            self._job, task_id, AbstractReport.Status.RUNNING.value
        )
        # monkeypatch if in test suite
        if settings.STAGE_CI or settings.MOCK_CONNECTIONS:
            self._monkeypatch()

    @classmethod
    @property
    @abstractmethod
    def python_base_path(cls) -> PosixPath:
        ...

    @classmethod
    def all_subclasses(cls):
        posix_dir = PosixPath(str(cls.python_base_path).replace(".", "/"))
        for plugin in posix_dir.rglob("*.py"):
            if plugin.stem == "__init__":
                continue

            package = f"{str(plugin.parent).replace('/', '.')}.{plugin.stem}"
            __import__(package)
        classes = cls.__subclasses__()
        return sorted(
            [class_ for class_ in classes if not class_.__name__.startswith("MockUp")],
            key=lambda x: x.__name__,
        )

    @cached_property
    def _job(self) -> "Job":
        return Job.objects.get(pk=self.job_id)

    @cached_property
    def _user(self):
        return self._job.user

    def __repr__(self):
        return f"({self.__class__.__name__}, job: #{self.job_id})"

    def _get_params(self) -> typing.Dict:
        return self._config.read_params(self._user, self.runtime_configuration)

    def config(self):
        for param, value in self._get_params().items():
            attribute_name = f"_{param.name}" if param.is_secret else param.name
            setattr(self, attribute_name, value)
            logger.debug(
                f"Adding to {self.__class__.__name__} "
                f"param {attribute_name} with value {value} "
            )

    def before_run(self):
        """
        function called directly before run function.
        """

    @abstractmethod
    def run(self) -> dict:
        """
        Called from *start* fn and wrapped in a try-catch block.
        Should be overwritten in child class
        :returns report
        """

    def after_run(self):
        """
        function called after run function.
        """
        self.report.end_time = timezone.now()
        self.report.save()

    def after_run_success(self, content: typing.Any):
        if isinstance(content, typing.Generator):
            content = list(content)
        self.report.report = content
        self.report.status = self.report.Status.SUCCESS.value
        self.report.save(update_fields=["status", "report"])

    def log_error(self, e):
        if isinstance(e, (*self.get_exceptions_to_catch(), SoftTimeLimitExceeded)):
            error_message = self.get_error_message(e)
            logger.error(error_message)
        else:
            traceback.print_exc()
            error_message = self.get_error_message(e, is_base_err=True)
            logger.exception(error_message)

    def after_run_failed(self, e: Exception):
        self.log_error(e)
        self.report.errors.append(str(e))
        self.report.status = self.report.Status.FAILED
        self.report.save(update_fields=["status", "errors"])
        if settings.STAGE_CI:
            raise e

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
    def config_model(cls) -> typing.Type[PythonConfig]:
        """
        Returns Model to be used for *init_report_object*
        """
        raise NotImplementedError()

    @abstractmethod
    def get_exceptions_to_catch(self) -> list:
        """
        Returns list of `Exception`'s to handle.
        """
        raise NotImplementedError()

    def get_error_message(self, err, is_base_err=False):
        """
        Returns error message for
        *_handle_analyzer_exception* and *_handle_base_exception* fn
        """
        return (
            f"{self.__repr__()}."
            f" {'Unexpected error' if is_base_err else f'{self.config_model.__name__} error'}:"  # noqa
            f" '{err}'"
        )

    def start(self, *args, **kwargs):
        """
        Entrypoint function to execute the plugin.
        calls `before_run`, `run`, `after_run`
        in that order with exception handling.
        """
        try:
            self.before_run()
            self.config()
            _result = self.run()
        except Exception as e:
            self.after_run_failed(e)
        else:
            self.after_run_success(_result)
        finally:
            # add end time of process
            self.after_run()

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
    def python_module(cls) -> PythonModule:
        valid_module = cls.__module__.replace(str(cls.python_base_path), "")
        # remove the starting dot
        valid_module = valid_module[1:]
        return PythonModule.objects.get(
            module=f"{valid_module}.{cls.__name__}", base_path=cls.python_base_path
        )
