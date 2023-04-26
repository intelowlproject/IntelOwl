# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from typing import Any, Dict, List, Type

from cache_memoize import cache_memoize
from django.conf import settings
from django.contrib.postgres import fields as pg_fields
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Manager, QuerySet
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.module_loading import import_string
from kombu import uuid

from api_app.core.choices import ParamTypes, Status
from api_app.validators import validate_config
from certego_saas.apps.organization.organization import Organization
from certego_saas.apps.user.models import User
from intel_owl.celery import DEFAULT_QUEUE, get_queue_name

logger = logging.getLogger(__name__)


class AbstractReport(models.Model):
    # constants
    Status = Status

    # fields
    status = models.CharField(max_length=50, choices=Status.choices)
    report = models.JSONField(default=dict)
    errors = pg_fields.ArrayField(
        models.CharField(max_length=512), default=list, blank=True
    )
    start_time = models.DateTimeField(default=timezone.now)
    end_time = models.DateTimeField(default=timezone.now)
    task_id = models.UUIDField()  # tracks celery task id

    job = models.ForeignKey(
        "api_app.Job", related_name="%(class)ss", on_delete=models.CASCADE
    )
    # meta

    class Meta:
        abstract = True
        unique_together = [("config", "job")]

    @classmethod
    @property
    def config(cls) -> "AbstractConfig":
        raise NotImplementedError()

    @property
    def runtime_configuration(self):
        return self.job.get_config_runtime_configuration(self.config)

    def __str__(self):
        return f"{self.__class__.__name__}(job:#{self.job_id}, {self.config.name})"

    # properties
    @property
    def user(self) -> models.Model:
        return self.job.user

    @property
    def process_time(self) -> float:
        secs = (self.end_time - self.start_time).total_seconds()
        return round(secs, 2)

    def update_status(self, status: str, save=True):
        self.status = status
        if save:
            self.save(update_fields=["status"])

    def append_error(self, err_msg: str, save=True):
        self.errors.append(err_msg)
        if save:
            self.save(update_fields=["errors"])


# This is required as a function (and not even a lambda)
# because the default must be a callable
def config_default():
    return dict(queue=DEFAULT_QUEUE, soft_time_limit=60)


class Parameter(models.Model):
    name = models.CharField(null=False, blank=False, max_length=50)
    type = models.CharField(
        choices=ParamTypes.choices, max_length=10, null=False, blank=False
    )
    description = models.TextField(blank=True, default="")
    is_secret = models.BooleanField(null=False)
    required = models.BooleanField(null=False)
    analyzer_config = models.ForeignKey(
        "analyzers_manager.AnalyzerConfig",
        related_name="parameters",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    connector_config = models.ForeignKey(
        "connectors_manager.ConnectorConfig",
        related_name="parameters",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    visualizer_config = models.ForeignKey(
        "visualizers_manager.VisualizerConfig",
        related_name="parameters",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )

    def clean_config(self):
        if (
            bool(self.analyzer_config)
            + bool(self.connector_config)
            + bool(self.visualizer_config)
            > 1
        ):
            raise ValidationError(
                "You cant have the same parameter on more than one configuration at the time"
            )

    def clean(self) -> None:
        super().clean()
        self.clean_config()

    class Meta:
        unique_together = [
            ("name", "analyzer_config", "connector_config", "visualizer_config")
        ]

    @cached_property
    def config(self):
        return self.analyzer_config or self.connector_config or self.visualizer_config

    def values_for_user(self, user: User = None) -> QuerySet:
        from api_app.models import PluginConfig

        return PluginConfig.visible_for_user(user).filter(parameter=self)

    def get_first_value(self, user: User = None) -> "PluginConfig":
        from api_app.models import PluginConfig

        # priority
        # 1 - Owner
        # 2 - Organization
        # 3 - Default
        qs = self.values_for_user(user)
        if not user:
            return qs.get(owner__isnull=True)
        else:
            try:
                return qs.get(owner=user)
            except PluginConfig.DoesNotExist:
                if user.has_membership():
                    try:
                        return qs.get(
                            for_organization=True,
                            owner=user.membership.organization.owner,
                        )
                    except PluginConfig.DoesNotExist:
                        ...
                return qs.get(owner__isnull=True)


class AbstractConfig(models.Model):

    parameters: Manager

    name = models.CharField(max_length=50, null=False, unique=True, primary_key=True)
    python_module = models.CharField(null=False, max_length=120, db_index=True)
    description = models.TextField(null=False)
    disabled = models.BooleanField(null=False, default=False)

    config = models.JSONField(
        blank=False,
        default=config_default,
        validators=[validate_config],
    )
    disabled_in_organizations = models.ManyToManyField(
        Organization, related_name="%(app_label)s_%(class)s_disabled", blank=True
    )

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=("python_module", "disabled")),
        ]

    @classmethod
    @property
    def snake_case_name(cls) -> str:
        import re

        return re.sub(r"(?<!^)(?=[A-Z])", "_", cls.__name__).lower()

    @classmethod
    @property
    def plugin_type(cls) -> str:
        # retro compatibility

        raise NotImplementedError()

    @property
    def python_base_path(self) -> str:
        raise NotImplementedError()

    def clean_python_module(self):
        try:
            _ = self.python_class
        except ImportError as exc:
            raise ValidationError(
                "`python_module` incorrect, "
                f"{self.python_complete_path} couldn't be imported"
            ) from exc

    def clean_config_queue(self):
        queue = self.config["queue"]
        if queue not in settings.CELERY_QUEUES:
            logger.warning(
                f"Analyzer {self.name} has a wrong queue."
                f" Setting to `{DEFAULT_QUEUE}`"
            )
            self.config["queue"] = DEFAULT_QUEUE

    def clean(self):
        super().clean()
        self.clean_python_module()
        self.clean_config_queue()

    @property
    def options(self):
        return self.parameters.filter(is_secret=False)

    @property
    def secrets(self):
        return self.parameters.filter(is_secret=True)

    @property
    def required_parameters(self) -> QuerySet:
        return self.parameters.filter(required=True)

    @cache_memoize(
        timeout=60 * 60 * 24 * 7,
        args_rewrite=lambda s, user=None: f"{s.__class__.__name__}"
        f"-{s.name}"
        f"-{user.username if user else ''}",
    )
    def get_verification(self, user: User = None):
        total_required = 0
        total_missing = 0
        parameter_required_missing: List[str] = []
        for param in self.required_parameters:
            param: Parameter
            total_required += 1
            if not param.values_for_user(user).exists():
                total_missing += 1
                parameter_required_missing.append(param.name)

        if total_missing:
            details = (
                f"{', '.join(parameter_required_missing)} "
                f"secret{''if len(parameter_required_missing) == 1 else 's'} not set;"
                f" ({total_required - total_missing} "
                f"of {total_required} satisfied)"
            )
        else:
            details = "Ready to use!"
        return {
            "configured": not total_missing,
            "details": details,
            "missing_secrets": parameter_required_missing,
        }

    def is_runnable(self, user: User = None):
        configured = False
        for param in self.required_parameters:
            param: Parameter
            if not param.values_for_user(user).exists()




        configured = self.get_verification(user)["configured"]
        if user and user.has_membership():
            disabled_by_org = self.disabled_in_organizations.filter(
                pk=user.membership.organization.pk
            ).exists()
        else:
            disabled_by_org = False
        logger.debug(f"{configured=}, {disabled_by_org=}, {self.disabled=}")
        return configured and not disabled_by_org and not self.disabled

    @cached_property
    def queue(self):
        queue = self.config["queue"]
        if queue not in settings.CELERY_QUEUES:
            queue = DEFAULT_QUEUE
        return get_queue_name(queue)

    @cached_property
    def routing_key(self):
        return self.config["queue"]

    @cached_property
    def soft_time_limit(self):
        return self.config["soft_time_limit"]

    @cached_property
    def python_complete_path(self) -> str:
        return f"{self.python_base_path}.{self.python_module}"

    @cached_property
    def python_class(self) -> Type:
        return import_string(self.python_complete_path)

    @classmethod
    @property
    def config_exception(cls):
        raise NotImplementedError()

    def read_params(self, job: "Job") -> Dict[str, Any]:
        # priority
        # 1 - Runtime config
        # 2 - Value inside the db
        result = {}
        for param in self.parameters.all():
            param: Parameter

            if param.name in job.get_config_runtime_configuration(self):
                result[param.name] = job.get_config_runtime_configuration(self)[
                    param.name
                ]
            else:
                result[param.name] = param.get_first_value(job.user).value
        return result

    def get_signature(self, job):
        from api_app.models import Job
        from intel_owl import tasks

        job: Job
        if self.is_runnable(job.user):
            # gen new task_id
            task_id = uuid()
            args = [
                job.pk,
                self.python_complete_path,
                self.pk,
                job.get_config_runtime_configuration(self),
                task_id,
            ]

            return tasks.run_plugin.signature(
                args,
                {},
                queue=self.queue,
                soft_time_limit=self.soft_time_limit,
                task_id=task_id,
                immutable=True,
                MessageGroupId=str(task_id),
            )
        raise RuntimeError(
            f"Unable to create signature, config {self.name} is not runnable"
        )
