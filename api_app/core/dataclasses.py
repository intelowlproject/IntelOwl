# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import dataclasses
import typing
from abc import abstractmethod
from logging import getLogger

import celery
from celery import uuid
from celery.canvas import Signature
from django.conf import settings
from django.utils.module_loading import import_string

from api_app.core.models import AbstractReport
from api_app.core.serializers import AbstractConfigSerializer
from api_app.models import Job, PluginConfig
from certego_saas.apps.user.models import User
from intel_owl.celery import DEFAULT_QUEUE
from intel_owl.consts import (
    DEFAULT_SOFT_TIME_LIMIT,
    PARAM_DATATYPE_CHOICES,
)

# otherwise we have a recursive import
logger = getLogger(__name__)


@dataclasses.dataclass
class _SecretsVerification:
    configured: bool
    error_message: typing.Optional[str]
    missing_secrets: typing.List


@dataclasses.dataclass
class _Config:
    queue: str = DEFAULT_QUEUE
    soft_time_limit: int = DEFAULT_SOFT_TIME_LIMIT


@dataclasses.dataclass
class _Param:
    value: typing.Any
    type: typing.Literal[PARAM_DATATYPE_CHOICES]
    description: str


@dataclasses.dataclass
class _Secret:
    env_var_key: str
    description: str
    required: bool
    type: typing.Literal[PARAM_DATATYPE_CHOICES] = None
    default: typing.Optional[typing.Any] = None


@dataclasses.dataclass
class AbstractConfig:
    name: str
    python_module: str
    disabled: bool
    description: str
    secrets: typing.Dict[str, _Secret]
    params: typing.Dict[str, _Param]
    config: _Config
    verification: _SecretsVerification

    @classmethod
    @abstractmethod
    def _get_serializer_class(cls) -> typing.Type[AbstractConfigSerializer]:
        raise NotImplementedError()

    @abstractmethod
    def _get_type(self) -> str:
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def _get_task(cls) -> celery.Task:
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def _get_report_model(cls) -> typing.Type[AbstractReport]:
        raise NotImplementedError()

    def __post_init__(self):
        secrets_values = list(self.secrets.values())
        params_values = list(self.params.values())
        # for nested dataclasses
        if isinstance(self.verification, dict):
            self.verification = _SecretsVerification(**self.verification)
        if isinstance(self.config, dict):
            self.config = _Config(**self.config)
        if params_values and isinstance(params_values[0], dict):
            self.params = {
                pname: _Param(**pdict) for pname, pdict in self.params.items()
            }
        if secrets_values and isinstance(secrets_values[0], dict):
            self.secrets = {
                sname: _Secret(**sdict) for sname, sdict in self.secrets.items()
            }

    # utils

    @property
    def is_configured(self) -> bool:
        return self.verification.configured

    @property
    def is_ready_to_use(self) -> bool:
        return not self.disabled and self.verification.configured

    @property
    def param_values(self) -> dict:
        return {name: param.value for name, param in self.params.items()}

    def read_secrets(
        self, secrets_filter=None, user: User = None
    ) -> typing.Dict[str, str]:
        """
        Returns a dict of `secret_key: secret_value` mapping.
        filter_secrets: filter specific secrets or not (default: return all)
        """
        if secrets_filter is None:
            secrets_filter = []
        secrets = {}
        if secrets_filter:
            _filtered_secrets = {
                key_name: self.secrets[key_name]
                for key_name in self.secrets.keys()
                if key_name in secrets_filter
            }
        else:
            _filtered_secrets = self.secrets
        for key_name, secret in _filtered_secrets.items():
            pcs = PluginConfig.visible_for_user(user).filter(
                attribute=key_name, type=self._get_type(), plugin_name=self.name
            )
            if pcs.count() > 1 and user:
                # I have both a secret from the org and the user, priority to the user
                value = pcs.get(owner=user, organization__isnull=True).value
            elif pcs.count() == 1:
                value = pcs.first().value
            elif secret.default is not None:
                value = secret.default
            else:
                value = None

            secrets[key_name] = value

        return secrets

    def get_class(self) -> typing.Type:
        """
        raises: ImportError
        """
        from api_app.core.classes import Plugin

        try:
            res: typing.Type[Plugin] = import_string(self.get_full_import_path())
        except ImportError:
            raise ImportError(
                f"Class: {self.get_full_import_path()} couldn't be imported"
            )
        else:
            return res

    @abstractmethod
    def get_full_import_path(self) -> str:
        raise NotImplementedError()

    # dataclass functionality extension

    @classmethod
    def from_dict(cls, data: dict) -> "AbstractConfig":
        return cls(**data)

    def asdict(self) -> dict:
        return dataclasses.asdict(self)

    # orm methods

    @classmethod
    def get(cls, name: str) -> typing.Optional["AbstractConfig"]:
        """
        Returns config dataclass by connector_name if found, else None
        """
        all_configs = cls._get_serializer_class().read_and_verify_config()
        config_dict = all_configs.get(name, None)
        if config_dict is None:
            return None  # not found
        return cls.from_dict(config_dict)

    @classmethod
    def all(cls) -> typing.Dict[str, "AbstractConfig"]:
        return {
            name: cls.from_dict(attrs)
            for name, attrs in cls._get_serializer_class()
            .read_and_verify_config()
            .items()
        }

    @classmethod
    def filter(cls, names: typing.List[str]) -> typing.Dict[str, "AbstractConfig"]:
        all_connector_configs = cls.all()
        return {name: cc for name, cc in all_connector_configs.items() if name in names}

    @classmethod
    def is_disabled(cls, class_name: str) -> bool:
        all_analyzer_config = cls.all()
        for ac in all_analyzer_config.values():
            if ac.python_module.endswith(f".{class_name}") and not ac.disabled:
                return False
        return True

    @classmethod
    def runnable(
        cls, plugin_to_execute: typing.List[str]
    ) -> typing.Tuple[typing.List[str], typing.List[str]]:
        plugin_dataclass = cls.filter(plugin_to_execute)
        plugins: typing.List[str] = []
        wrong_plugins: typing.List[str] = []
        for plugin_name in plugin_to_execute:
            plugin = plugin_dataclass.get(plugin_name)
            if not plugin:
                logger.error(f"There is no {cls.__name__} with name {plugin_name}")
                wrong_plugins.append(plugin_name)
            else:
                if plugin.is_ready_to_use or settings.STAGE_CI:
                    plugins.append(plugin_name)
        return plugins, wrong_plugins

    @classmethod
    def stack(
        cls,
        job_id: int,
        plugins_to_execute: typing.List[str],
        runtime_configuration: typing.Dict[str, typing.Dict] = None,
        parent_playbook: str = "",
    ) -> typing.Tuple[typing.List[Signature], typing.List[str]]:
        # to store the celery task signatures
        task_signatures = []
        plugins_used = []

        plugins_to_run, wrong_plugins = cls.runnable(plugins_to_execute)

        plugin_dataclasses = cls.all()
        # get job
        job = Job.objects.get(pk=job_id)
        # set invalid plugins as errors
        for plugin in wrong_plugins:
            job.append_error(f"Unable to find plugin {plugin}")
        job.update_status(Job.Status.RUNNING)  # set job status to running

        # loop over and create task signatures
        for plugin_name in plugins_to_run:
            # get corresponding dataclass
            config = plugin_dataclasses.get(plugin_name, None)

            # if disabled or unconfigured (this check is bypassed in STAGE_CI)
            if not config.is_ready_to_use and not settings.STAGE_CI:
                logger.info(
                    f"skipping execution of plugin {plugin_name}, job_id {job_id}"
                )
                continue

            # get runtime_configuration if any specified for this analyzer
            runtime_params = runtime_configuration.get(plugin_name, {})
            # gen new task_id
            task_id = uuid()
            # construct arguments
            args = [
                job_id,
                config.asdict(),
                {
                    "runtime_configuration": runtime_params,
                    "task_id": task_id,
                    "parent_playbook": parent_playbook,
                },
            ]
            # get celery queue
            queue = config.config.queue
            if queue not in settings.CELERY_QUEUES:
                logger.warning(
                    f"Analyzer {plugin_name} has a wrong queue."
                    f" Setting to `{DEFAULT_QUEUE}`"
                )
                queue = DEFAULT_QUEUE
            # get soft_time_limit
            soft_time_limit = config.config.soft_time_limit
            # create task signature and add to list
            task_signatures.append(
                cls._get_task().signature(
                    args,
                    {},
                    queue=queue,
                    soft_time_limit=soft_time_limit,
                    task_id=task_id,
                    immutable=True,
                )
            )
            plugins_used.append(plugin_name)

        return task_signatures, plugins_used

    def run(self, job_id: int, report_defaults: dict) -> AbstractReport:
        try:
            class_ = self.get_class()
        except ImportError as e:
            report = self._get_report_model().get_or_create_failed(
                job_id, self.name, report_defaults, str(e)
            )
        else:
            instance = class_(
                config=self, job_id=job_id, report_defaults=report_defaults
            )
            try:
                report = instance.start()
            except Exception as e:
                report = self._get_report_model().get_or_create_failed(
                    job_id, self.name, report_defaults, str(e)
                )
        return report
