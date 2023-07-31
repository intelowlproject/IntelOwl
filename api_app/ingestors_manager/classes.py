# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import logging
import typing
from collections import deque
from typing import Any, Type

from django.conf import settings
from django.utils.functional import cached_property

from ..choices import TLP
from ..classes import Plugin
from .exceptions import IngestorConfigurationException, IngestorRunException
from .models import IngestorConfig, IngestorReport

logger = logging.getLogger(__name__)


class Ingestor(Plugin, metaclass=abc.ABCMeta):

    maximum_jobs: int = None

    def __init__(self, config: IngestorConfig, runtime_configuration: dict, **kwargs):
        super().__init__(
            config,
            job_id=None,
            runtime_configuration=runtime_configuration,
            task_id=None,
            **kwargs
        )

    @classmethod
    @property
    def python_base_path(cls):
        return settings.BASE_INGESTOR_PYTHON_PATH

    @abc.abstractmethod
    def run(self) -> typing.Iterator[Any]:
        ...

    @classmethod
    @property
    def report_model(cls) -> Type[IngestorReport]:
        return IngestorReport

    @classmethod
    @property
    def config_model(cls) -> Type[IngestorConfig]:
        return IngestorConfig

    def get_exceptions_to_catch(self) -> list:
        return [
            IngestorConfigurationException,
            IngestorRunException,
        ]

    @cached_property
    def _user(self):
        self._config: IngestorConfig
        return self._config.user

    def after_run_success(self, content):
        super().after_run_success(content)
        self._config: IngestorConfig
        # exhaust generator
        deque(
            self._config._create_jobs(
                # every job created from an ingestor
                self.report,
                TLP.CLEAR.value,
                self._user,
            ),
            maxlen=0,
        )

    def execute_pivots(self) -> None:
        # we do not have a job, meaning that we have no pivots
        return

    @cached_property
    def _job(self) -> None:
        return None

    def init_report_object(self) -> IngestorReport:
        """
        Returns report object set in *__init__* fn
        """
        # every time we execute the ingestor we have to create a new report
        # instead of using the update/create
        # because we do not have the same unique constraints
        _report = self.report_model.objects.create(
            job_id=self.job_id,
            config=self._config,
            status=IngestorReport.Status.PENDING.value,
            task_id=self.task_id,
            max_size_report=self.maximum_jobs,
        )
        return _report
