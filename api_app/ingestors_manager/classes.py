# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import logging
import typing
from collections import deque
from typing import Any, Type

from django.utils.functional import cached_property

from ..choices import TLP, PythonModuleBasePaths
from ..classes import Plugin
from .exceptions import IngestorConfigurationException, IngestorRunException
from .models import IngestorConfig, IngestorReport

logger = logging.getLogger(__name__)


class Ingestor(Plugin, metaclass=abc.ABCMeta):
    def __init__(self, config: IngestorConfig, **kwargs):
        super().__init__(config, **kwargs)

    @classmethod
    @property
    def python_base_path(cls):
        return PythonModuleBasePaths.Ingestor.value

    @abc.abstractmethod
    def run(self) -> typing.Iterator[Any]:
        raise NotImplementedError()

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

    def before_run(self):
        self._config: IngestorConfig
        self._config.validate_playbook_to_execute(self._user)

    def after_run_success(self, content):
        super().after_run_success(content)
        self._config: IngestorConfig
        # exhaust generator
        deque(
            self._config.create_jobs(
                # every job created from an ingestor
                content,
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
