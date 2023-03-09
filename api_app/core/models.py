# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from typing import Any, Dict, Type

from cache_memoize import cache_memoize
from django.conf import settings
from django.contrib.postgres import fields as pg_fields
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.module_loading import import_string
from kombu import uuid

from api_app.validators import validate_config, validate_params, validate_secrets
from certego_saas.apps.organization.organization import Organization
from certego_saas.apps.user.models import User
from intel_owl.celery import DEFAULT_QUEUE

logger = logging.getLogger(__name__)


class Status(models.TextChoices):
    FAILED = "FAILED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    KILLED = "KILLED"


class AbstractReport(models.Model):
    # constants
    Status = Status

    # fields
    status = models.CharField(max_length=50, choices=Status.choices)
    report = models.JSONField(default=dict)
    errors = pg_fields.ArrayField(
        models.CharField(max_length=512), default=list, blank=True
    )
    runtime_configuration = models.JSONField(default=dict, null=True, blank=True)
    start_time = models.DateTimeField(default=timezone.now)
    end_time = models.DateTimeField(default=timezone.now)
    task_id = models.UUIDField()  # tracks celery task id

    # If a playbook ran the process
    parent_playbook = models.CharField(max_length=128, default="", blank=True)
    job = models.ForeignKey(
        "api_app.Job", related_name="%(class)ss", on_delete=models.CASCADE
    )

    @classmethod
    @property
    def config(cls) -> "AbstractConfig":
        raise NotImplementedError()

    # meta
    class Meta:
        abstract = True
        unique_together = [("config", "job")]

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

    @classmethod
    def get_or_create_failed(
        cls, job_id: int, config: "AbstractConfig", defaults: Dict, error: str
    ) -> "AbstractReport":
        logger.warning(
            f"(job: #{job_id}, {cls.__name__}:{config.name}) -> "
            f"set as {cls.Status.FAILED}. "
            f"Error: {error}"
        )
        report, _ = cls.objects.get_or_create(
            job_id=job_id, config=config, defaults=defaults
        )
        report.status = cls.Status.FAILED
        report.errors.append(error)
        report.save()
        return report


# This is required as a function (and not even a lambda)
# because the default must be a callable
def config_default():
    return dict(queue=DEFAULT_QUEUE, soft_time_limit=60)


class AbstractConfig(models.Model):
    name = models.CharField(max_length=50, null=False, unique=True, primary_key=True)
    python_module = models.CharField(null=False, max_length=120, db_index=True)
    description = models.TextField(null=False)
    disabled = models.BooleanField(null=False, default=False)

    config = models.JSONField(
        blank=False,
        default=config_default,
        validators=[validate_config],
    )
    secrets = models.JSONField(blank=True, default=dict, validators=[validate_secrets])
    params = models.JSONField(blank=True, default=dict, validators=[validate_params])
    disabled_in_organizations = models.ManyToManyField(
        Organization, related_name="%(app_label)s_%(class)s_disabled", blank=True
    )

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=("python_module", "disabled")),
        ]

    @classmethod
    def _get_type(cls) -> models.TextChoices:
        raise NotImplementedError()

    @property
    def python_path(self) -> str:
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

    @classmethod
    @property
    def report_model(cls) -> Type[AbstractReport]:
        raise NotImplementedError()

    @cache_memoize(
        timeout=60 * 60 * 24,
        args_rewrite=lambda s, user=None: f"{s.__class__.__name__}"
        f"-{s.name}"
        f"-{user.username if user else ''}",
    )
    def get_verification(self, user: User = None):
        from api_app.models import PluginConfig

        missing_secrets = []
        configured = True
        for secret, value in self.secrets.items():
            if (
                not PluginConfig.visible_for_user(user)
                .filter(
                    attribute=secret,
                    type=self._get_type(),
                    plugin_name=self.name,
                )
                .exists()
            ):
                missing_secrets.append(secret)
                if value["required"]:
                    configured = False

        num_missing_secrets = len(missing_secrets)
        num_total_secrets = len(self.secrets.keys())
        if missing_secrets:
            details = (
                f"{', '.join(missing_secrets)} "
                f"{'facultative' if configured else ''} "
                f"secret{''if len(missing_secrets) == 1 else 's'} not set;"
                f" ({num_total_secrets - num_missing_secrets} "
                f"of {num_total_secrets} satisfied)"
            )
        else:
            details = "Ready to use!"

        return {
            "configured": configured,
            "details": details,
            "missing_secrets": missing_secrets,
        }

    def is_runnable(self, user: User = None):
        configured = self.get_verification(user)["configured"]
        if user and user.has_membership():
            disabled_by_org = self.disabled_in_organizations.filter(
                pk=user.membership.organization.pk
            ).exists()
        else:
            disabled_by_org = False

        return configured and not disabled_by_org and not self.disabled

    @cached_property
    def queue(self):
        return self.config["queue"]

    @cached_property
    def soft_time_limit(self):
        return self.config["soft_time_limit"]

    @cached_property
    def python_complete_path(self) -> str:
        return f"{self.python_path}.{self.python_module}"

    @cached_property
    def python_class(self) -> Type:
        return import_string(self.python_complete_path)

    @classmethod
    @property
    def config_exception(cls):
        raise NotImplementedError()

    def _read_plugin_config(
        self,
        config_type: str,
        user: User = None,
    ):
        from api_app.models import PluginConfig

        config = {}
        if config_type == PluginConfig.ConfigType.PARAMETER:
            attr = self.params
        elif config_type == PluginConfig.ConfigType.SECRET:
            attr = self.secrets
        else:
            raise TypeError(f"Unable to retrieve config type {config_type}")
        for key, secret_config in attr.items():
            pcs = PluginConfig.visible_for_user(user).filter(
                attribute=key,
                type=self._get_type(),
                plugin_name=self.name,
                config_type=config_type,
            )
            if pcs.count() > 1 and user:
                # I have both a secret from the org and the user, priority to the user
                value = pcs.get(owner=user, organization__isnull=True).value
            elif pcs.count() == 1:
                value = pcs.first().value
            elif "default" in secret_config:
                value = secret_config["default"]
            elif "required" in secret_config and secret_config["required"]:
                raise self.config_exception(
                    f"{self.name}:"
                    f" {PluginConfig.ConfigType(config_type).label}"
                    f" {key} is missing"
                )
            else:
                continue
            config[key] = value
        return config

    def read_secrets(self, user: User = None) -> Dict[str, Any]:
        from api_app.models import PluginConfig

        return self._read_plugin_config(PluginConfig.ConfigType.SECRET, user)

    def read_params(self, user: User = None) -> Dict[str, Any]:
        from api_app.models import PluginConfig

        return self._read_plugin_config(PluginConfig.ConfigType.PARAMETER, user)

    def run(self, job_id: int, report_defaults: dict) -> AbstractReport:
        class_ = self.python_class
        instance = class_(config=self, job_id=job_id, report_defaults=report_defaults)
        try:
            report = instance.start()
        except Exception as e:
            report = self.report_model.get_or_create_failed(
                job_id, self, report_defaults, str(e)
            )
        return report

    def get_signature(
        self, job_id: int, runtime_configuration: Dict, parent_playbook: str
    ):
        from api_app.models import Job
        from intel_owl import tasks

        job = Job.objects.get(pk=job_id)
        if self.is_runnable(job.user):
            # gen new task_id
            task_id = uuid()
            args = [
                job_id,
                self.python_complete_path,
                self.pk,
                {
                    "runtime_configuration": runtime_configuration,
                    "task_id": task_id,
                    "parent_playbook": parent_playbook,
                },
            ]

            return tasks.run_plugin.signature(
                args,
                {},
                queue=self.queue,
                soft_time_limit=self.soft_time_limit,
                task_id=task_id,
                immutable=True,
            )
        raise RuntimeError(
            f"Unable to create signature, config {self.name} is not runnable"
        )
