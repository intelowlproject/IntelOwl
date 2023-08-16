# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import base64
import datetime
import logging
import typing
import uuid
from typing import Any, Dict, Optional, Type

from celery import group
from celery.canvas import Signature
from django.conf import settings
from django.contrib.postgres import fields as pg_fields
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator, RegexValidator
from django.db import models
from django.db.models import Manager, QuerySet
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.module_loading import import_string

from api_app.choices import (
    TLP,
    ObservableClassification,
    ParamTypes,
    ReportStatus,
    ScanMode,
    Status,
)
from api_app.defaults import config_default, default_runtime, file_directory_path
from api_app.helpers import calculate_sha1, calculate_sha256, deprecated, get_now
from api_app.queryset import (
    AbstractConfigQuerySet,
    JobQuerySet,
    ParameterQuerySet,
    PluginConfigQuerySet,
    PythonConfigQuerySet,
)
from api_app.validators import (
    plugin_name_validator,
    validate_config,
    validate_runtime_configuration,
)
from certego_saas.apps.organization.organization import Organization
from certego_saas.models import User
from intel_owl import tasks
from intel_owl.celery import DEFAULT_QUEUE, get_queue_name

logger = logging.getLogger(__name__)


class Tag(models.Model):
    label = models.CharField(
        max_length=50,
        blank=False,
        null=False,
        unique=True,
        validators=[MinLengthValidator(4)],
    )
    color = models.CharField(
        max_length=7,
        blank=False,
        null=False,
        validators=[RegexValidator(r"^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$", "Hex color")],
    )

    def __str__(self):
        return f'Tag(label="{self.label}")'


class Comment(models.Model):
    # make the user null if the user is deleted
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="comment",
    )

    class Meta:
        ordering = ["created_at"]

    job = models.ForeignKey(
        "Job",
        on_delete=models.CASCADE,
        related_name="comments",
    )
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Job(models.Model):

    objects = JobQuerySet.as_manager()

    class Meta:
        indexes = [
            models.Index(
                fields=[
                    "md5",
                    "status",
                ]
            ),
            models.Index(
                fields=["playbook_to_execute", "finished_analysis_time", "user"],
                name="PlaybookConfigOrdering",
            ),
        ]

    # constants
    TLP = TLP
    Status = Status

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,  # for backwards compatibility
    )
    is_sample = models.BooleanField(blank=False, default=False)
    md5 = models.CharField(max_length=32, blank=False)
    observable_name = models.CharField(max_length=512, blank=True)
    observable_classification = models.CharField(
        max_length=12, blank=True, choices=ObservableClassification.choices
    )
    file_name = models.CharField(max_length=512, blank=True)
    file_mimetype = models.CharField(max_length=80, blank=True)
    status = models.CharField(
        max_length=32, blank=False, choices=Status.choices, default="pending"
    )

    analyzers_requested = models.ManyToManyField(
        "analyzers_manager.AnalyzerConfig", related_name="requested_in_jobs", blank=True
    )
    connectors_requested = models.ManyToManyField(
        "connectors_manager.ConnectorConfig",
        related_name="requested_in_jobs",
        blank=True,
    )
    playbook_requested = models.ForeignKey(
        "playbooks_manager.PlaybookConfig",
        related_name="requested_in_jobs",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )

    analyzers_to_execute = models.ManyToManyField(
        "analyzers_manager.AnalyzerConfig", related_name="executed_in_jobs", blank=True
    )
    connectors_to_execute = models.ManyToManyField(
        "connectors_manager.ConnectorConfig",
        related_name="executed_in_jobs",
        blank=True,
    )
    visualizers_to_execute = models.ManyToManyField(
        "visualizers_manager.VisualizerConfig",
        related_name="executed_in_jobs",
        blank=True,
    )
    playbook_to_execute = models.ForeignKey(
        "playbooks_manager.PlaybookConfig",
        related_name="executed_in_jobs",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    runtime_configuration = models.JSONField(
        blank=False,
        default=default_runtime,
        null=False,
        validators=[validate_runtime_configuration],
    )
    received_request_time = models.DateTimeField(auto_now_add=True, db_index=True)
    finished_analysis_time = models.DateTimeField(blank=True, null=True)
    process_time = models.FloatField(blank=True, null=True)
    tlp = models.CharField(max_length=8, choices=TLP.choices, default=TLP.CLEAR)
    errors = pg_fields.ArrayField(
        models.CharField(max_length=900), blank=True, default=list, null=True
    )
    file = models.FileField(blank=True, upload_to=file_directory_path)
    tags = models.ManyToManyField(Tag, related_name="jobs", blank=True)

    scan_mode = models.IntegerField(
        choices=ScanMode.choices,
        null=False,
        blank=False,
        default=ScanMode.CHECK_PREVIOUS_ANALYSIS.value,
    )
    scan_check_time = models.DurationField(
        null=True, blank=True, default=datetime.timedelta(hours=24)
    )

    def __str__(self):
        return f'{self.__class__.__name__}(#{self.pk}, "{self.analyzed_object_name}")'

    @property
    def analyzed_object_name(self):
        return self.file_name if self.is_sample else self.observable_name

    @cached_property
    def sha256(self) -> str:
        return calculate_sha256(
            self.file.read() if self.is_sample else self.observable_name.encode("utf-8")
        )

    @cached_property
    def sha1(self) -> str:
        return calculate_sha1(
            self.file.read() if self.is_sample else self.observable_name.encode("utf-8")
        )

    @cached_property
    def b64(self) -> str:
        return base64.b64encode(
            self.file.read() if self.is_sample else self.observable_name.encode("utf-8")
        ).decode("utf-8")

    def get_absolute_url(self):
        return reverse("jobs-detail", args=[self.pk])

    @property
    def url(self):
        return settings.WEB_CLIENT_URL + self.get_absolute_url()

    def retry(self):

        self.update_status(Job.Status.RUNNING)
        failed_analyzers_reports = self.analyzerreports.filter(
            status=AbstractReport.Status.FAILED.value
        ).values_list("pk", flat=True)
        failed_connector_reports = self.connectorreports.filter(
            status=AbstractReport.Status.FAILED.value
        ).values_list("pk", flat=True)
        failed_visualizer_reports = self.visualizerreports.filter(
            status=AbstractReport.Status.FAILED.value
        ).values_list("pk", flat=True)

        runner = (
            self._get_signatures(
                self.analyzers_to_execute.filter(pk__in=failed_analyzers_reports)
            )
            | self._get_signatures(
                self.connectors_to_execute.filter(pk__in=failed_connector_reports)
            )
            | self._get_signatures(
                self.visualizers_to_execute.filter(pk__in=failed_visualizer_reports)
            )
        )
        return runner()

    def set_final_status(self) -> None:
        logger.info(f"[STARTING] set_final_status for <-- {self}.")

        if self.status == self.Status.FAILED:
            logger.error(
                f"[REPORT] {self}, status: failed. " "Do not process the report"
            )
        else:
            stats = self._get_config_reports_stats()
            logger.info(f"[REPORT] {self}, status:{self.status}, reports:{stats}")

            if stats["success"] == stats["all"]:
                self.status = self.Status.REPORTED_WITHOUT_FAILS
            elif stats["failed"] == stats["all"]:
                self.status = self.Status.FAILED
            elif stats["killed"] == stats["all"]:
                self.status = self.Status.KILLED
            elif stats["failed"] >= 1 or stats["killed"] >= 1:
                self.status = self.Status.REPORTED_WITH_FAILS

        if not self.finished_analysis_time:
            self.finished_analysis_time = get_now()
            self.process_time = self.calculate_process_time()
        logger.info(f"{self.__repr__()} setting status to {self.status}")
        self.save(
            update_fields=[
                "status",
                "errors",
                "finished_analysis_time",
                "process_time",
            ]
        )

    def calculate_process_time(self) -> Optional[float]:
        if not self.finished_analysis_time:
            return None
        td = self.finished_analysis_time - self.received_request_time
        return round(td.total_seconds(), 2)

    def append_error(self, err_msg: str, save=True) -> None:
        self.errors.append(err_msg)
        if save:
            self.save(update_fields=["errors"])

    def update_status(self, status: str, save=True) -> None:
        self.status = status
        if save:
            self.save(update_fields=["status"])

    def _get_config_reports(self, config: typing.Type["AbstractConfig"]) -> QuerySet:
        return getattr(self, f"{config.__name__.split('Config')[0].lower()}reports")

    def _get_config_to_execute(self, config: typing.Type["AbstractConfig"]) -> QuerySet:
        return getattr(
            self, f"{config.__name__.split('Config')[0].lower()}s_to_execute"
        )

    def _get_single_config_reports_stats(
        self, config: typing.Type["AbstractConfig"]
    ) -> typing.Dict:
        reports = self._get_config_reports(config)
        aggregators = {
            s.lower(): models.Count("status", filter=models.Q(status=s))
            for s in AbstractReport.Status.values
        }
        return reports.aggregate(
            all=models.Count("status"),
            **aggregators,
        )

    def _get_config_reports_stats(self) -> typing.Dict:
        from api_app.analyzers_manager.models import AnalyzerConfig
        from api_app.connectors_manager.models import ConnectorConfig
        from api_app.visualizers_manager.models import VisualizerConfig

        result = {}
        for config in [AnalyzerConfig, ConnectorConfig, VisualizerConfig]:
            partial_result = self._get_single_config_reports_stats(config)
            # merge them
            result = {
                k: result.get(k, 0) + partial_result.get(k, 0)
                for k in set(result) | set(partial_result)
            }
        return result

    def kill_if_ongoing(self):
        from api_app.analyzers_manager.models import AnalyzerConfig
        from api_app.connectors_manager.models import ConnectorConfig
        from api_app.visualizers_manager.models import VisualizerConfig
        from intel_owl.celery import app as celery_app

        for config in [AnalyzerConfig, ConnectorConfig, VisualizerConfig]:

            reports = self._get_config_reports(config).filter(
                status__in=[
                    AbstractReport.Status.PENDING,
                    AbstractReport.Status.RUNNING,
                ]
            )

            ids = list(reports.values_list("task_id", flat=True))
            logger.info(f"We are going to kill tasks {ids}")
            # kill celery tasks using task ids
            celery_app.control.revoke(ids, terminate=True)

            reports.update(status=self.Status.KILLED)

        # set job status
        self.update_status(self.Status.KILLED)

    def _get_signatures(self, queryset: QuerySet) -> Signature:
        config_class: PythonConfig = queryset.model
        signatures = list(
            queryset.annotate_runnable(self.user)
            .filter(runnable=True)
            .get_signatures(self)
        )
        logger.info(f"{config_class} signatures are {signatures}")

        return (
            config_class.signature_pipeline_running(self)
            | group(signatures)
            | config_class.signature_pipeline_completed(self)
        )

    def execute(self):
        self.update_status(Job.Status.RUNNING)
        runner = (
            self._get_signatures(self.analyzers_to_execute.all())
            | self._get_signatures(self.connectors_to_execute.all())
            | self._get_signatures(self.visualizers_to_execute.all())
            | tasks.job_set_final_status.signature(
                args=[self.pk],
                kwargs={},
                queue=get_queue_name(DEFAULT_QUEUE),
                soft_time_limit=10,
                immutable=True,
                MessageGroupId=str(uuid.uuid4()),
            )
        )
        runner()

    def get_config_runtime_configuration(self, config: "AbstractConfig") -> typing.Dict:
        try:
            self._get_config_to_execute(config.__class__).get(name=config.name)
        except config.DoesNotExist:
            raise TypeError(
                f"{config.__class__.__name__} {config.name} "
                f"is not configured inside job {self.pk}"
            )
        return self.runtime_configuration[config.runtime_configuration_key].get(
            config.name, {}
        )

    # user methods

    @classmethod
    def user_total_submissions(cls, user: User) -> int:
        return user.job_set.count()

    @classmethod
    def user_month_submissions(cls, user: User) -> int:
        """
        Excludes failed submissions.
        """
        return (
            user.job_set.filter(
                received_request_time__gte=timezone.now().replace(
                    day=1, hour=0, minute=0, second=0, microsecond=0
                )
            )
            .exclude(status=cls.Status.FAILED)
            .count()
        )

    def clean(self) -> None:
        self.clean_scan()

    def clean_scan(self):
        if (
            self.scan_mode == ScanMode.FORCE_NEW_ANALYSIS.value
            and self.scan_check_time is not None
        ):
            raise ValidationError(
                f"You can't have set mode to {ScanMode.FORCE_NEW_ANALYSIS.name}"
                f" and have check_time set to {self.scan_check_time}"
            )
        elif (
            self.scan_mode == ScanMode.CHECK_PREVIOUS_ANALYSIS.value
            and self.scan_check_time is None
        ):
            raise ValidationError(
                f"You can't have set mode to {ScanMode.CHECK_PREVIOUS_ANALYSIS.name}"
                " and not have check_time set"
            )


class Parameter(models.Model):

    objects = ParameterQuerySet.as_manager()

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
    ingestor_config = models.ForeignKey(
        "ingestors_manager.IngestorConfig",
        related_name="parameters",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )

    class Meta:
        unique_together = [
            ("name", "analyzer_config"),
            ("name", "connector_config"),
            ("name", "visualizer_config"),
            ("name", "ingestor_config"),
        ]
        indexes = [
            models.Index(fields=["analyzer_config", "is_secret"]),
            models.Index(fields=["connector_config", "is_secret"]),
            models.Index(fields=["visualizer_config", "is_secret"]),
            models.Index(fields=["ingestor_config", "is_secret"]),
        ]

    def clean_config(self):
        count_configs = (
            bool(self.analyzer_config)
            + bool(self.connector_config)
            + bool(self.visualizer_config)
            + bool(self.ingestor_config)
        )

        if count_configs > 1:
            msg = (
                "You can't have the same parameter on more than one"
                " configuration at the time"
            )
            logger.error(msg)
            raise ValidationError(msg)
        elif count_configs == 0:
            msg = "The parameter must be set to at least a configuration"
            logger.error(msg)
            raise ValidationError(msg)

    def clean(self) -> None:
        super().clean()
        self.clean_config()

    @cached_property
    def config(self):
        return (
            self.analyzer_config
            or self.connector_config
            or self.visualizer_config
            or self.ingestor_config
        )

    def get_valid_value_for_test(self):
        if not settings.STAGE_CI and not settings.MOCK_CONNECTIONS:
            raise PluginConfig.DoesNotExist
        if "url" in self.name:
            return "https://intelowl.com"
        elif "pdns_credentials" == self.name:
            return "user|pwd"
        elif "test" in self.name:
            raise PluginConfig.DoesNotExist
        else:
            return "test"


class PluginConfig(models.Model):

    objects = PluginConfigQuerySet.as_manager()

    value = models.JSONField(blank=True, null=True)
    for_organization = models.BooleanField(default=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="custom_configs",
        null=True,
        blank=True,
    )
    parameter = models.ForeignKey(
        Parameter, on_delete=models.CASCADE, null=False, related_name="values"
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ["owner", "for_organization", "parameter"]
        indexes = [
            models.Index(fields=["owner", "for_organization", "parameter"]),
            models.Index(
                fields=[
                    "owner",
                    "for_organization",
                ]
            ),
            models.Index(
                fields=[
                    "owner",
                ]
            ),
        ]

    def clean_for_organization(self):
        if self.for_organization and not self.owner:
            raise ValidationError(
                "You can't set `for_organization` and not have an owner"
            )
        if self.for_organization and not self.owner.has_membership():
            raise ValidationError(
                f"You can't create `for_organization` {self.__class__.__name__}"
                " if you do not have an organization"
            )

    def clean_value(self):
        from django.forms.fields import JSONString

        if isinstance(self.value, JSONString):
            self.value = str(self.value)
        if type(self.value).__name__ != self.parameter.type:
            raise ValidationError(
                f"Type {type(self.value).__name__} is wrong:"
                f" should be {self.parameter.type}"
            )

    def clean(self):
        super().clean()
        self.clean_value()
        self.clean_for_organization()

    @property
    def attribute(self):
        return self.parameter.name

    def is_secret(self):
        return self.parameter.is_secret

    @property
    def plugin_name(self):
        return self.config.name

    @property
    def config(self):
        return self.parameter.config

    @property
    def type(self):
        # TODO retrocompatibility
        return self.config.plugin_type

    @cached_property
    def organization(self):
        if self.for_organization:
            return self.owner.membership.organization.name
        return None

    @property
    def config_type(self):
        # TODO retrocompatibility
        return "2" if self.is_secret() else "1"


class AbstractConfig(models.Model):
    objects = AbstractConfigQuerySet.as_manager()
    name = models.CharField(
        max_length=100,
        null=False,
        unique=True,
        primary_key=True,
        validators=[plugin_name_validator],
    )
    description = models.TextField(null=False)

    disabled = models.BooleanField(null=False, default=False)
    disabled_in_organizations = models.ManyToManyField(
        Organization, related_name="%(app_label)s_%(class)s_disabled", blank=True
    )

    class Meta:
        indexes = [models.Index(fields=["name"]), models.Index(fields=["disabled"])]
        abstract = True

    @classmethod
    @property
    def runtime_configuration_key(cls) -> str:
        return f"{cls.__name__.split('Config')[0].lower()}s"

    @classmethod
    @property
    def snake_case_name(cls) -> str:
        import re

        return re.sub(r"(?<!^)(?=[A-Z])", "_", cls.__name__).lower()

    @deprecated("Please use `runnable` method on queryset")
    def is_runnable(self, user: User = None) -> bool:
        return (
            self.__class__.objects.filter(pk=self.pk)
            .annotate_runnable(user)
            .first()
            .runnable
        )


class AbstractReport(models.Model):
    # constants
    Status = ReportStatus

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

    class Meta:
        abstract = True

    def __str__(self):
        return f"{self.__class__.__name__}(job:#{self.job_id}, {self.config.name})"

    @classmethod
    @property
    def config(cls) -> "AbstractConfig":
        raise NotImplementedError()

    @property
    def runtime_configuration(self):
        return self.job.get_config_runtime_configuration(self.config)

    # properties
    @property
    def user(self) -> models.Model:
        return self.job.user

    @property
    def process_time(self) -> float:
        secs = (self.end_time - self.start_time).total_seconds()
        return round(secs, 2)

    def append_error(self, err_msg: str, save=True):
        self.errors.append(err_msg)
        if save:
            self.save(update_fields=["errors"])


class PythonConfig(AbstractConfig):
    objects = PythonConfigQuerySet.as_manager()
    parameters: Manager

    python_module = models.CharField(null=False, max_length=120, db_index=True)

    config = models.JSONField(
        blank=False,
        default=config_default,
        validators=[validate_config],
    )

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=("python_module", "disabled")),
        ]
        ordering = ["name", "disabled"]

    @classmethod
    @property
    def plugin_type(cls) -> str:
        # retro compatibility

        raise NotImplementedError()

    @classmethod
    @property
    def plugin_name(cls) -> str:
        return cls.__name__.split("Config")[0]

    @classmethod
    def signature_pipeline_running(cls, job) -> Signature:
        return cls._signature_pipeline_status(
            job, getattr(Status, f"{cls.plugin_name.upper()}S_RUNNING").value
        )

    @classmethod
    def signature_pipeline_completed(cls, job) -> Signature:
        return cls._signature_pipeline_status(
            job, getattr(Status, f"{cls.plugin_name.upper()}S_COMPLETED").value
        )

    @classmethod
    def _signature_pipeline_status(cls, job, status: str) -> Signature:
        return tasks.job_set_pipeline_status.signature(
            args=[job.pk, status],
            kwargs={},
            queue=get_queue_name(DEFAULT_QUEUE),
            soft_time_limit=10,
            immutable=True,
            MessageGroupId=str(uuid.uuid4()),
        )

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
    def options(self) -> QuerySet:
        return self.parameters.filter(is_secret=False)

    @property
    def secrets(self) -> QuerySet:
        return self.parameters.filter(is_secret=True)

    @property
    def required_parameters(self) -> QuerySet:
        return self.parameters.filter(required=True)

    @deprecated("Please use the queryset method `annotate_configured`.")
    def _is_configured(self, user: User = None) -> bool:
        pc = self.__class__.objects.filter(pk=self.pk).annotate_configured(user).first()
        return pc.configured

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

    def read_params(
        self, user: User = None, config_runtime: Dict = None
    ) -> Dict[Parameter, Any]:
        # priority
        # 1 - Runtime config
        # 2 - Value inside the db
        result = {}
        for param in self.parameters.annotate_configured(user).annotate_value_for_user(
            user
        ):
            param: Parameter
            if param.name in config_runtime:
                result[param] = config_runtime[param.name]
            else:
                if param.configured:
                    result[param] = param.value
                else:
                    if settings.STAGE_CI or settings.MOCK_CONNECTIONS:
                        result[param] = param.get_valid_value_for_test()
                        continue
                    if param.required:
                        raise TypeError(
                            f"Required param {param.name} of plugin {param.config.name}"
                            " does not have a valid value"
                        )
        return result
