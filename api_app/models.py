# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import base64
import datetime
import json
import logging
import typing
import uuid
from typing import TYPE_CHECKING, Any, Dict, Optional, Type

from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.utils.timezone import now
from django_celery_beat.models import ClockedSchedule, CrontabSchedule, PeriodicTask
from treebeard.mp_tree import MP_Node

from api_app.interfaces import OwnershipAbstractModel

if TYPE_CHECKING:
    from api_app.serializers import PythonConfigSerializer

from celery import group
from celery.canvas import Signature
from django.conf import settings
from django.contrib.postgres import fields as pg_fields
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.validators import MinLengthValidator, MinValueValidator, RegexValidator
from django.db import models
from django.db.models import BaseConstraint, Q, QuerySet, UniqueConstraint
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.module_loading import import_string

from api_app.choices import (
    TLP,
    ObservableClassification,
    ParamTypes,
    PythonModuleBasePaths,
    ReportStatus,
    ScanMode,
    Status,
)

if typing.TYPE_CHECKING:
    from api_app.classes import Plugin

from api_app.defaults import default_runtime, file_directory_path
from api_app.helpers import calculate_sha1, calculate_sha256, deprecated, get_now
from api_app.queryset import (
    AbstractConfigQuerySet,
    AbstractReportQuerySet,
    JobQuerySet,
    OrganizationPluginConfigurationQuerySet,
    ParameterQuerySet,
    PluginConfigQuerySet,
    PythonConfigQuerySet,
)
from api_app.validators import plugin_name_validator, validate_runtime_configuration
from certego_saas.apps.organization.organization import Organization
from certego_saas.models import User
from intel_owl import tasks
from intel_owl.celery import get_queue_name

logger = logging.getLogger(__name__)


class PythonModule(models.Model):
    module = models.CharField(max_length=120, db_index=True)
    base_path = models.CharField(
        max_length=120, db_index=True, choices=PythonModuleBasePaths.choices
    )
    update_schedule = models.ForeignKey(
        CrontabSchedule,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="update_for_%(class)s",
    )
    update_task = models.OneToOneField(
        PeriodicTask,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="update_for_%(class)s",
        editable=False,
    )

    health_check_schedule = models.ForeignKey(
        CrontabSchedule,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="healthcheck_for_%(class)s",
    )

    class Meta:
        unique_together = [["module", "base_path"]]
        ordering = ["base_path", "module"]

    def __str__(self):
        return self.module

    def __contains__(self, item: str):
        if not isinstance(item, str) and not isinstance(item, PythonConfig):
            raise TypeError(f"{self.__class__.__name__} needs a string or pythonConfig")
        if isinstance(item, str):
            return item in self.python_complete_path
        elif isinstance(item, PythonConfig):
            return self.configs.filter(name=item.name).exists()

    @cached_property
    def python_complete_path(self) -> str:
        return f"{self.base_path}.{self.module}"

    @property
    def disabled(self):
        # it is disabled if it does not exist a configuration enabled
        return not self.configs.filter(disabled=False).exists()

    @cached_property
    def python_class(self) -> Type["Plugin"]:
        return import_string(self.python_complete_path)

    @property
    def configs(self) -> PythonConfigQuerySet:
        return self.config_class.objects.filter(python_module__pk=self.pk)

    @cached_property
    def config_class(self) -> Type["PythonConfig"]:
        return self.python_class.config_model

    @property
    def queue(self) -> str:
        try:
            return self.configs.order_by("?").first().queue
        except AttributeError:
            return None

    def _clean_python_module(self):
        try:
            _ = self.python_class
        except ImportError as exc:
            raise ValidationError(
                "`python_module` incorrect, "
                f"{self.python_complete_path} couldn't be imported"
            ) from exc

    def clean(self) -> None:
        super().clean()
        self._clean_python_module()

    def generate_update_periodic_task(self):
        from intel_owl.tasks import update

        if hasattr(self, "update_schedule") and self.update_schedule:
            enabled = settings.REPO_DOWNLOADER_ENABLED and not self.disabled
            periodic_task = PeriodicTask.objects.update_or_create(
                name=f"{self.python_complete_path}Update",
                task=f"{update.__module__}.{update.__name__}",
                defaults={
                    "crontab": self.update_schedule,
                    "queue": self.queue,
                    "enabled": enabled,
                    "kwargs": json.dumps({"python_module_pk": self.pk}),
                },
            )[0]
            self.update_task = periodic_task


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
        return self.label


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


class Job(MP_Node):
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
            models.Index(
                fields=["sent_to_bi", "-received_request_time"], name="JobBISearch"
            ),
        ]

    # constants
    TLP = TLP
    Status = Status
    investigation = models.ForeignKey(
        "investigations_manager.Investigation",
        on_delete=models.PROTECT,
        related_name="jobs",
        null=True,
        blank=True,
        default=None,
    )
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
    warnings = pg_fields.ArrayField(
        models.TextField(), blank=True, default=list, null=True
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
    sent_to_bi = models.BooleanField(editable=False, default=False)

    def __str__(self):
        return f'{self.__class__.__name__}(#{self.pk}, "{self.analyzed_object_name}")'

    def get_root(self):
        if self.is_root():
            return self
        try:
            return super().get_root()
        except self.MultipleObjectsReturned:
            # django treebeard is not thread safe
            # this is not a really valid solution, but it will work for now
            return self.objects.filter(path=self.path[0 : self.steplen]).first()  # noqa

    @property
    def analyzed_object_name(self):
        return self.file_name if self.is_sample else self.observable_name

    @property
    def analyzed_object(self):
        return self.file if self.is_sample else self.observable_name

    @cached_property
    def sha256(self) -> str:
        return calculate_sha256(
            self.file.read() if self.is_sample else self.observable_name.encode("utf-8")
        )

    @cached_property
    def parent_job(self) -> Optional["Job"]:
        return self.get_parent()

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
        return self.get_absolute_url_by_pk(self.pk)

    @classmethod
    def get_absolute_url_by_pk(cls, pk: int):
        return reverse("jobs-detail", args=[pk]).removeprefix("/api")

    @property
    def url(self):
        return settings.WEB_CLIENT_URL + self.get_absolute_url()

    def retry(self):
        self.status = self.Status.RUNNING
        self.save(update_fields=["status"])

        runner = self._get_pipeline(
            analyzers=self.analyzerreports.filter_retryable().get_configurations(),
            pivots=self.pivotreports.filter_retryable().get_configurations(),
            connectors=self.connectorreports.filter_retryable().get_configurations(),
            visualizers=self.visualizerreports.filter_retryable().get_configurations(),
        )

        runner.apply_async(
            queue=get_queue_name(settings.CONFIG_QUEUE),
            MessageGroupId=str(uuid.uuid4()),
            priority=self.priority,
        )

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

        self.finished_analysis_time = get_now()

        logger.info(f"{self.__repr__()} setting status to {self.status}")
        self.save(
            update_fields=[
                "status",
                "errors",
                "finished_analysis_time",
            ]
        )
        try:
            # we update the status of the analysis
            if root_investigation := self.get_root().investigation:
                root_investigation.set_correct_status(save=True)
        except Exception as e:
            logger.exception(
                f"investigation status not updated. Job: {self.pk}. Error: {e}"
            )

    def __get_config_reports(self, config: typing.Type["AbstractConfig"]) -> QuerySet:
        return getattr(self, f"{config.__name__.split('Config')[0].lower()}reports")

    def __get_config_to_execute(
        self, config: typing.Type["AbstractConfig"]
    ) -> QuerySet:
        return getattr(
            self, f"{config.__name__.split('Config')[0].lower()}s_to_execute"
        )

    def __get_single_config_reports_stats(
        self, config: typing.Type["AbstractConfig"]
    ) -> typing.Dict:
        reports = self.__get_config_reports(config)
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
            partial_result = self.__get_single_config_reports_stats(config)
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
        from api_app.websocket import JobConsumer
        from intel_owl.celery import app as celery_app

        for config in [AnalyzerConfig, ConnectorConfig, VisualizerConfig]:
            reports = self.__get_config_reports(config).filter(
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

        self.status = self.Status.KILLED
        self.save(update_fields=["status"])
        JobConsumer.serialize_and_send_job(self)

    def _get_signatures(self, queryset: PythonConfigQuerySet) -> Signature:
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

    @cached_property
    def pivots_to_execute(self) -> PythonConfigQuerySet:
        from api_app.pivots_manager.models import PivotConfig

        if self.playbook_to_execute:
            pivots = self.playbook_to_execute.pivots.all()
        else:
            pivots = PivotConfig.objects.valid(
                self.analyzers_to_execute.all(), self.connectors_to_execute.all()
            )
        return pivots.annotate_runnable(self.user).filter(runnable=True)

    @property
    def _final_status_signature(self) -> Signature:
        return tasks.job_set_final_status.signature(
            args=[self.pk],
            kwargs={},
            queue=get_queue_name(settings.CONFIG_QUEUE),
            immutable=True,
            MessageGroupId=str(uuid.uuid4()),
            priority=self.priority,
        )

    @property
    def priority(self):
        return self.user.profile.task_priority

    def _get_pipeline(
        self,
        analyzers: PythonConfigQuerySet,
        pivots: PythonConfigQuerySet,
        connectors: PythonConfigQuerySet,
        visualizers: PythonConfigQuerySet,
    ) -> Signature:
        runner = self._get_signatures(analyzers.distinct())
        pivots_analyzers = pivots.filter(
            related_analyzer_configs__isnull=False
        ).distinct()
        if pivots_analyzers.exists():
            runner |= self._get_signatures(pivots_analyzers)
        if connectors.exists():
            runner |= self._get_signatures(connectors)
            pivots_connectors = pivots.filter(
                related_connector_configs__isnull=False
            ).distinct()
            if pivots_connectors.exists():
                runner |= self._get_signatures(pivots_connectors)
        if visualizers.exists():
            runner |= self._get_signatures(visualizers)
        runner |= self._final_status_signature
        return runner

    def execute(self):
        self.status = self.Status.RUNNING
        self.save(update_fields=["status"])
        runner = self._get_pipeline(
            self.analyzers_to_execute.all(),
            self.pivots_to_execute.all(),
            self.connectors_to_execute.all(),
            self.visualizers_to_execute.all(),
        )
        runner()

    def get_config_runtime_configuration(self, config: "AbstractConfig") -> typing.Dict:
        try:
            self.__get_config_to_execute(config.__class__).get(name=config.name)
        except config.DoesNotExist:
            raise TypeError(
                f"{config.__class__.__name__} {config.name} "
                f"is not configured inside job {self.pk}"
            )
        return self.runtime_configuration.get(config.runtime_configuration_key, {}).get(
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
        super().clean()
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
    is_secret = models.BooleanField(db_index=True)
    required = models.BooleanField(null=False)
    python_module = models.ForeignKey(
        PythonModule, related_name="parameters", on_delete=models.CASCADE
    )

    class Meta:
        unique_together = [["name", "python_module"]]

    def __str__(self):
        return self.name

    def refresh_cache_keys(self):
        self.config_class.delete_class_cache_keys()
        for config in self.config_class.objects.filter(
            python_module=self.python_module
        ):
            config: PythonConfig
            config.refresh_cache_keys()

    @cached_property
    def config_class(self) -> Type["PythonConfig"]:
        return self.python_module.python_class.config_model


class PluginConfig(OwnershipAbstractModel):
    objects = PluginConfigQuerySet.as_manager()
    value = models.JSONField(blank=True, null=True)

    parameter = models.ForeignKey(
        Parameter, on_delete=models.CASCADE, null=False, related_name="values"
    )
    updated_at = models.DateTimeField(auto_now=True)
    analyzer_config = models.ForeignKey(
        "analyzers_manager.AnalyzerConfig",
        related_name="values",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    connector_config = models.ForeignKey(
        "connectors_manager.ConnectorConfig",
        related_name="values",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    visualizer_config = models.ForeignKey(
        "visualizers_manager.VisualizerConfig",
        related_name="values",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    ingestor_config = models.ForeignKey(
        "ingestors_manager.IngestorConfig",
        on_delete=models.CASCADE,
        related_name="values",
        null=True,
        blank=True,
    )
    pivot_config = models.ForeignKey(
        "pivots_manager.PivotConfig",
        on_delete=models.CASCADE,
        related_name="values",
        null=True,
        blank=True,
    )

    class Meta:
        constraints: typing.List[BaseConstraint] = [
            models.CheckConstraint(
                check=Q(analyzer_config__isnull=True)
                | Q(connector_config__isnull=True)
                | Q(visualizer_config__isnull=True)
                | Q(ingestor_config__isnull=True)
                | Q(pivot_config__isnull=True),
                name="plugin_config_no_config_all_null",
            )
        ] + [
            item
            for config in [
                "analyzer_config",
                "connector_config",
                "visualizer_config",
                "ingestor_config",
                "pivot_config",
            ]
            for item in [
                UniqueConstraint(
                    fields=["owner", "for_organization", "parameter", config],
                    name=f"plugin_config_unique_with_{config}_owner",
                    condition=Q(owner__isnull=False),
                ),
                UniqueConstraint(
                    fields=["for_organization", "parameter", config],
                    name=f"plugin_config_unique_with_{config}",
                    condition=Q(owner__isnull=True),
                ),
            ]
        ]
        indexes = [
            models.Index(fields=["owner", "for_organization", "parameter"]),
        ] + OwnershipAbstractModel.Meta.indexes

    @cached_property
    def config(self) -> "PythonConfig":
        return list(filter(None, self._possible_configs()))[0]

    def refresh_cache_keys(self):
        try:
            _ = self.config and self.owner
        except ObjectDoesNotExist:
            # this happens if the configuration/user was deleted before this instance
            return
        if self.owner:
            if self.owner.has_membership() and self.owner.membership.is_admin:
                for user in User.objects.filter(
                    membership__organization=self.owner.membership.organization
                ):
                    self.config.delete_class_cache_keys(user)
                    self.config.refresh_cache_keys(user)
            else:
                self.owner: User
                self.config.delete_class_cache_keys(self.owner)
                self.config.refresh_cache_keys(self.owner)

        else:
            self.config.delete_class_cache_keys()
            self.config.refresh_cache_keys()

    def _possible_configs(self) -> typing.List["PythonConfig"]:
        return [
            self.analyzer_config,
            self.connector_config,
            self.visualizer_config,
            self.ingestor_config,
            self.pivot_config,
        ]

    def clean_config(self) -> None:
        if len(list(filter(None, self._possible_configs()))) != 1:
            configs = ", ".join(
                [config.name for config in self._possible_configs() if config]
            )
            if not configs:
                raise ValidationError("You must select a plugin configuration")
            raise ValidationError(f"You must have exactly one between {configs}")

    def clean_value(self):
        from django.forms.fields import JSONString

        if isinstance(self.value, JSONString):
            self.value = str(self.value)
        if type(self.value).__name__ != self.parameter.type:
            raise ValidationError(
                f"Type {type(self.value).__name__} is wrong:"
                f" should be {self.parameter.type}"
            )

    def clean_parameter(self):
        if self.config.python_module != self.parameter.python_module:
            raise ValidationError(
                f"Missmatch between config python module {self.config.python_module}"
                f" and parameter python module {self.parameter.python_module}"
            )

    def clean(self):
        super().clean()
        self.clean_value()
        self.clean_for_organization()
        self.clean_config()
        self.clean_parameter()

    @property
    def attribute(self):
        return self.parameter.name

    def is_secret(self):
        return self.parameter.is_secret

    @property
    def plugin_name(self):
        return self.config.name

    @property
    def type(self):
        # TODO retrocompatibility
        return self.config.plugin_type

    @property
    def config_type(self):
        # TODO retrocompatibility
        return "2" if self.is_secret() else "1"


class OrganizationPluginConfiguration(models.Model):
    objects = OrganizationPluginConfigurationQuerySet.as_manager()
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        limit_choices_to={
            "model__endswith": "config",
            "app_label__endswith": "manager",
        },
    )
    object_id = models.IntegerField()
    config = GenericForeignKey("content_type", "object_id")

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

    disabled = models.BooleanField(default=False)
    disabled_comment = models.TextField(default="", blank=True)

    rate_limit_timeout = models.DurationField(
        null=True, blank=True, help_text="Expects data in the format 'DD HH:MM:SS'"
    )
    rate_limit_enable_task = models.ForeignKey(
        PeriodicTask, on_delete=models.SET_NULL, null=True, blank=True, editable=False
    )

    class Meta:
        unique_together = [("object_id", "organization", "content_type")]

    def __str__(self):
        return f"{self.config} ({self.organization})"

    def disable_for_rate_limit(self):
        self.disabled = True

        enabled_to = now() + self.rate_limit_timeout
        self.disabled_comment = (
            "Rate limit hit at "
            f"{now().strftime('%d %m %Y: %H %M %S')}.\n"
            "Will be enabled back at "
            f"{enabled_to.strftime('%d %m %Y: %H %M %S')}"
        )
        clock_schedule = ClockedSchedule.objects.get_or_create(clocked_time=enabled_to)[
            0
        ]
        if not self.rate_limit_enable_task:
            from intel_owl.tasks import enable_configuration_for_org_for_rate_limit

            self.rate_limit_enable_task = PeriodicTask.objects.create(
                name=f"{self.config.name}"
                f"-{self.organization.name}"
                "RateLimitCleaner",
                clocked=clock_schedule,
                one_off=True,
                enabled=True,
                task=f"{enable_configuration_for_org_for_rate_limit.__name__}",
                kwargs=json.dumps(
                    {
                        "org_configuration_pk": self.pk,
                    }
                ),
            )
        else:
            self.rate_limit_enable_task.clocked = clock_schedule
            self.rate_limit_enable_task.enabled = True
            self.rate_limit_enable_task.save()
        logger.warning(f"Disabling {self} for rate limit")
        self.save()

    def disable_manually(self, user: User):
        self.disabled = True
        self.disabled_comment = (
            f"Disabled by user {user.username}"
            f" at {now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        if self.rate_limit_enable_task:
            self.rate_limit_enable_task.delete()
        self.save()

    def enable_manually(self, user: User):
        self.disabled_comment += (
            f"\nEnabled back by {user.username}"
            f" at {now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.enable()

    def enable(self):
        logger.info(f"Enabling back {self}")
        self.disabled = False
        self.disabled_comment = ""
        self.save()
        if self.rate_limit_enable_task:
            self.rate_limit_enable_task.delete()


class ListCachable(models.Model):
    class Meta:
        abstract = True

    @classmethod
    def delete_class_cache_keys(cls, user: User = None):
        base_key = f"{cls.__name__}_{user.username if user else ''}"
        for key in cache.get_where(f"list_{base_key}").keys():
            logger.debug(f"Deleting cache key {key}")
            cache.delete(key)

    @classmethod
    @property
    def python_path(cls) -> str:
        return f"{cls.__module__}.{cls.__name__}"


class AbstractConfig(ListCachable):
    objects = AbstractConfigQuerySet.as_manager()
    name = models.CharField(
        max_length=100,
        null=False,
        unique=True,
        validators=[plugin_name_validator],
    )
    description = models.TextField(null=False)

    disabled = models.BooleanField(null=False, default=False)
    orgs_configuration = GenericRelation(OrganizationPluginConfiguration)

    class Meta:
        indexes = [models.Index(fields=["name"]), models.Index(fields=["disabled"])]
        abstract = True

    def __str__(self):
        return self.name

    def get_or_create_org_configuration(
        self, organization: Organization
    ) -> OrganizationPluginConfiguration:
        try:
            org_configuration = self.orgs_configuration.get(organization=organization)
        except OrganizationPluginConfiguration.DoesNotExist:
            org_configuration = OrganizationPluginConfiguration.objects.create(
                config=self, organization=organization
            )
        return org_configuration

    @classmethod
    def get_content_type(cls) -> ContentType:
        return ContentType.objects.get(
            model=cls._meta.model_name, app_label=cls._meta.app_label
        )

    @property
    def disabled_in_organizations(self) -> QuerySet:
        return self.orgs_configuration.filter(disabled=True)

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

    def enabled_for_user(self, user: User) -> bool:
        if user.has_membership():
            return (
                not self.disabled
                and not self.orgs_configuration.filter(
                    disabled=True, organization__pk=user.membership.organization_id
                ).exists()
            )
        return not self.disabled


class AbstractReport(models.Model):
    objects = AbstractReportQuerySet.as_manager()
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
    parameters = models.JSONField(blank=False, null=False, editable=False)
    sent_to_bi = models.BooleanField(default=False, editable=False)

    class Meta:
        abstract = True
        indexes = [
            models.Index(
                fields=["sent_to_bi", "-start_time"], name="%(class)ssBISearch"
            )
        ]

    def __str__(self):
        return f"{self.__class__.__name__}(job:#{self.job_id}, {self.config.name})"

    @classmethod
    @property
    def config(cls) -> "AbstractConfig":
        raise NotImplementedError()

    @cached_property
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


class PythonConfig(AbstractConfig):
    objects = PythonConfigQuerySet.as_manager()
    soft_time_limit = models.IntegerField(default=60, validators=[MinValueValidator(0)])
    routing_key = models.CharField(max_length=50, default="default")
    python_module = models.ForeignKey(
        PythonModule, on_delete=models.PROTECT, related_name="%(class)ss"
    )

    health_check_task = models.OneToOneField(
        PeriodicTask,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="healthcheck_for_%(class)s",
        editable=False,
    )
    health_check_status = models.BooleanField(default=True, editable=False)

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=("python_module", "disabled")),
        ]
        ordering = ["name", "disabled"]

    def get_routing_key(self) -> str:
        if self.routing_key not in settings.CELERY_QUEUES:
            logger.warning(
                f"{self.name}: you have no worker for {self.routing_key}."
                f" Using {settings.DEFAULT_QUEUE} queue."
            )
            return settings.DEFAULT_QUEUE
        return self.routing_key

    @property
    def parameters(self) -> ParameterQuerySet:
        return Parameter.objects.filter(python_module=self.python_module)

    @classmethod
    @property
    def report_class(cls) -> Type[AbstractReport]:
        return cls.reports.rel.related_model

    @classmethod
    def get_subclasses(cls) -> typing.List["PythonConfig"]:
        child_models = [ct.model_class() for ct in ContentType.objects.all()]
        return [
            model
            for model in child_models
            if (model is not None and issubclass(model, cls) and model is not cls)
        ]

    @classmethod
    @property
    def plugin_type(cls) -> str:
        # retro compatibility

        raise NotImplementedError()

    def _get_params(self, user: User, runtime_configuration: Dict) -> Dict[str, Any]:
        return {
            parameter.name: parameter.value
            for parameter in self.read_configured_params(user, runtime_configuration)
            if not parameter.is_secret
        }

    def generate_empty_report(self, job: Job, task_id: str, status: str):
        return self.python_module.python_class.report_model.objects.update_or_create(
            job=job,
            config=self,
            defaults={
                "status": status,
                "task_id": task_id,
                "start_time": now(),
                "end_time": now(),
                "parameters": self._get_params(
                    job.user, job.get_config_runtime_configuration(self)
                ),
            },
        )[0]

    def refresh_cache_keys(self, user: User = None):
        from api_app.serializers.plugin import PythonConfigListSerializer

        base_key = (
            f"{self.__class__.__name__}_{self.name}_{user.username if user else ''}"
        )
        for key in cache.get_where(f"serializer_{base_key}").keys():
            logger.debug(f"Deleting cache key {key}")
            cache.delete(key)
        if user:
            PythonConfigListSerializer(
                child=self.serializer_class()
            ).to_representation_single_plugin(self, user)
        else:
            for generic_user in User.objects.exclude(email=""):
                PythonConfigListSerializer(
                    child=self.serializer_class()
                ).to_representation_single_plugin(self, generic_user)

    @classmethod
    @property
    def serializer_class(cls) -> Type["PythonConfigSerializer"]:
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
            queue=get_queue_name(settings.CONFIG_QUEUE),
            immutable=True,
            MessageGroupId=str(uuid.uuid4()),
            priority=job.priority,
        )

    @property
    def queue(self):
        return get_queue_name(self.get_routing_key())

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

    @classmethod
    @property
    def config_exception(cls):
        raise NotImplementedError()

    def read_configured_params(
        self, user: User = None, config_runtime: Dict = None
    ) -> ParameterQuerySet:
        params = self.parameters.annotate_configured(
            self, user
        ).annotate_value_for_user(self, user, config_runtime)
        not_configured_params = params.filter(required=True, configured=False)
        # TODO to optimize
        if not_configured_params.exists():
            param = not_configured_params.first()
            if not settings.STAGE_CI or settings.STAGE_CI and not param.value:
                raise TypeError(
                    f"Required param {param.name} "
                    f"of plugin {param.python_module.module}"
                    " does not have a valid value"
                )
        if settings.STAGE_CI:
            return params.filter(Q(configured=True) | Q(value__isnull=False))
        return params.filter(configured=True)

    def generate_health_check_periodic_task(self):
        from intel_owl.tasks import health_check

        if (
            hasattr(self.python_module, "health_check_schedule")
            and self.python_module.health_check_schedule
        ):
            periodic_task = PeriodicTask.objects.update_or_create(
                name=f"{self.name.title()}HealthCheck{self.__class__.__name__}",
                task=f"{health_check.__module__}.{health_check.__name__}",
                defaults={
                    "crontab": self.python_module.health_check_schedule,
                    "queue": self.queue,
                    "enabled": not self.disabled,
                    "kwargs": json.dumps(
                        {
                            "python_module_pk": self.python_module_id,
                            "plugin_config_pk": self.pk,
                        }
                    ),
                },
            )[0]
            self.health_check_task = periodic_task
            self.save()
