# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
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

from api_app.analyzables_manager.models import Analyzable
from api_app.data_model_manager.queryset import BaseDataModelQuerySet
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
    ParamTypes,
    PythonModuleBasePaths,
    ReportStatus,
    ScanMode,
    Status,
)

if typing.TYPE_CHECKING:
    from api_app.classes import Plugin

from api_app.defaults import default_runtime
from api_app.helpers import deprecated, get_now
from api_app.queryset import (
    AbstractConfigQuerySet,
    AbstractReportQuerySet,
    CommentQuerySet,
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
    """
    Represents a Python module model used in the application.

    Attributes:
        module (str): The name of the module.
        base_path (str): The base path where the module is located.
        update_schedule (CrontabSchedule): The schedule for updating the module.
        update_task (PeriodicTask): The task associated with updating the module.
        health_check_schedule (CrontabSchedule): The schedule for health checks.
    """

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
        """
        Check if a string or PythonConfig is in the module.

        Args:
            item (str or PythonConfig): The item to check.

        Returns:
            bool: True if the item is in the module, False otherwise.
        """
        if not isinstance(item, str) and not isinstance(item, PythonConfig):
            raise TypeError(f"{self.__class__.__name__} needs a string or pythonConfig")
        if isinstance(item, str):
            return item in self.python_complete_path
        elif isinstance(item, PythonConfig):
            return self.configs.filter(name=item.name).exists()

    @cached_property
    def python_complete_path(self) -> str:
        """
        Get the complete path of the Python module.

        Returns:
            str: The complete path.
        """
        return f"{self.base_path}.{self.module}"

    @property
    def disabled(self):
        """
        Check if the module is disabled.

        Returns:
            bool: True if disabled, False otherwise.
        """
        # it is disabled if it does not exist a configuration enabled
        return not self.configs.filter(disabled=False).exists()

    @cached_property
    def python_class(self) -> Type["Plugin"]:
        """
        Get the class of the Python module.

        Returns:
            Type[Plugin]: The class.
        """
        return import_string(self.python_complete_path)

    @property
    def configs(self) -> PythonConfigQuerySet:
        """
        Get the configurations of the module.

        Returns:
            PythonConfigQuerySet: The configurations.
        """
        return self.config_class.objects.filter(python_module__pk=self.pk)

    @cached_property
    def config_class(self) -> Type["PythonConfig"]:
        """
        Get the configuration class of the module.

        Returns:
            Type[PythonConfig]: The configuration class.
        """
        return self.python_class.config_model

    @property
    def queue(self) -> str:
        """
        Get the queue associated with the module.

        Returns:
            str: The queue.
        """
        try:
            return self.configs.order_by("?").first().queue
        except AttributeError:
            return None

    def _clean_python_module(self):
        """
        Validate the Python module.

        Raises:
            ValidationError: If the module cannot be imported.
        """
        try:
            _ = self.python_class
        except ImportError as exc:
            raise ValidationError(
                "`python_module` incorrect, "
                f"{self.python_complete_path} couldn't be imported"
            ) from exc

    def clean(self) -> None:
        """
        Clean the Python module.
        """
        super().clean()
        self._clean_python_module()

    def generate_update_periodic_task(self):
        """
        Generate a periodic task for updating the module.
        """
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
    """
    Represents a tag associated with an object.

    Attributes:
        label (str): The label of the tag.
        color (str): The color of the tag in hex format.
    """

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
    """
    Represents a comment on a job.

    Attributes:
        user (User): The user who made the comment.
        job (Job): The job associated with the comment.
        content (str): The content of the comment.
        created_at (datetime): The date and time when the comment was created.
        updated_at (datetime): The date and time when the comment was last updated.
    """

    # make the user null if the user is deleted
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="comment",
    )

    analyzable = models.ForeignKey(
        "analyzables_manager.Analyzable",
        on_delete=models.CASCADE,
        related_name="comments",
    )
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CommentQuerySet.as_manager()

    class Meta:
        ordering = ["created_at"]


class Job(MP_Node):
    """
    Represents a job in the system, which is a task or process that is being managed.

    Attributes:
        TLP (str): The TLP (Traffic Light Protocol) level.
        Status (str): The status of the job.
        investigation (Investigation): The investigation associated with the job.
        user (User): The user who created the job.
        is_sample (bool): Indicates if the job is a sample.
        md5 (str): The MD5 hash of the job.
        observable_name (str): The name of the observable.
        observable_classification (str): The classification of the observable.
        file_name (str): The name of the file.
        file_mimetype (str): The MIME type of the file.
        status (str): The current status of the job.
        analyzers_requested (ManyToManyField): The analyzers requested for the job.
        analyzers_dispatched (ManyToManyField): The analyzers dispatched for the job.
        analyzers_completed (ManyToManyField): The analyzers completed for the job.
        analyzers_report (ManyToManyField): The analyzers report for the job.
        analyzers_started (ManyToManyField): The analyzers started for the job.
    """

    objects = JobQuerySet.as_manager()

    class Meta:
        indexes = [
            models.Index(fields=["data_model_content_type", "data_model_object_id"]),
            models.Index(
                fields=[
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
            # SELECT COUNT(*) AS "__count" FROM "api_app_job"
            # WHERE ("api_app_job"."depth" >= ? AND "api_app_job"."path"::text LIKE ? AND NOT ("api_app_job"."id" = ?))
            models.Index(fields=["depth", "path", "id"], name="MPNodeSearch"),
        ]

    # constants
    TLP = TLP
    STATUSES = Status
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

    analyzable = models.ForeignKey(
        Analyzable, related_name="jobs", on_delete=models.CASCADE
    )

    status = models.CharField(
        max_length=32, blank=False, choices=STATUSES.choices, default="pending"
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
    data_model_content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        limit_choices_to={
            "app_label": "data_model_manager",
        },
        null=True,
        editable=False,
        blank=True,
    )
    data_model_object_id = models.IntegerField(null=True, editable=False, blank=True)
    data_model = GenericForeignKey("data_model_content_type", "data_model_object_id")

    def __str__(self):
        return f'{self.__class__.__name__}(#{self.pk}, "{self.analyzable.name}")'

    def get_root(self):
        if self.is_root():
            return self
        try:
            return super().get_root()
        except self.MultipleObjectsReturned:
            # django-treebeard is not thread safe - this indicates a data
            # integrity issue. We intentionally avoid select_for_update() to
            # prevent potential database deadlocks in high-concurrency
            # environments (e.g., multiple Celery workers).
            # Using order_by('pk').first() ensures all concurrent requests
            # get the same deterministic root node, even if multiple roots
            # exist due to a race condition.
            # Note: The root cause is in django-treebeard's tree modification
            # operations, not in this read operation.
            root_node = (
                type(self)
                .objects.filter(path=self.path[: self.steplen])
                .order_by("pk")
                .first()
            )
            logger.warning(
                f"Tree Integrity Error: Multiple roots found for Job {self.pk} "
                f"(path: {self.path}). Returning deterministic root "
                f"(PK: {root_node.pk if root_node else 'None'}) as fallback."
            )
            return root_node

    @cached_property
    def is_sample(self) -> bool:
        return self.analyzable.is_sample

    @cached_property
    def parent_job(self) -> Optional["Job"]:
        """
        Return the parent job if it exists, otherwise return None.
        """
        return self.get_parent()

    def get_absolute_url(self):
        """
        Return the absolute URL for the job details.
        """
        return self.get_absolute_url_by_pk(self.pk)

    @classmethod
    def get_absolute_url_by_pk(cls, pk: int):
        """
        Return the absolute URL for the job details by primary key.
        """
        return reverse("jobs-detail", args=[pk]).removeprefix("/api")

    @property
    def url(self):
        """
        Return the web client URL for the job details.
        """
        return settings.WEB_CLIENT_URL + self.get_absolute_url()

    def retry(self):
        """
        Retry the job by setting its status to running and re-executing the pipeline.
        """
        self.status = self.STATUSES.RUNNING
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

        if self.status == self.STATUSES.FAILED:
            logger.error(
                f"[REPORT] {self}, status: failed. " "Do not process the report"
            )
        else:
            stats = self._get_config_reports_stats()
            logger.info(f"[REPORT] {self}, status:{self.status}, reports:{stats}")

            if stats["success"] == stats["all"]:
                self.status = self.STATUSES.REPORTED_WITHOUT_FAILS
            elif stats["failed"] == stats["all"]:
                self.status = self.STATUSES.FAILED
            elif stats["killed"] == stats["all"]:
                self.status = self.STATUSES.KILLED
            elif stats["failed"] >= 1 or stats["killed"] >= 1:
                self.status = self.STATUSES.REPORTED_WITH_FAILS

        self.finished_analysis_time = get_now()

        logger.info(f"{self.__repr__()} setting status to {self.status}")
        self.save(
            update_fields=[
                "status",
                "errors",
                "finished_analysis_time",
            ]
        )
        # we update the status of the analysis
        if root_investigation := self.get_root().investigation:
            from api_app.investigations_manager.models import Investigation

            logger.info(f"Updating status of investigation {root_investigation.pk}")
            root_investigation: Investigation
            root_investigation.set_correct_status(save=True)

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
            for s in AbstractReport.STATUSES.values
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
                    AbstractReport.STATUSES.PENDING,
                    AbstractReport.STATUSES.RUNNING,
                ]
            )

            ids = list(reports.values_list("task_id", flat=True))
            logger.info(f"We are going to kill tasks {ids}")
            # kill celery tasks using task ids
            celery_app.control.revoke(ids, terminate=True)

            reports.update(status=self.STATUSES.KILLED, end_time=now())

        self.status = self.STATUSES.KILLED
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

    def _get_engine_signature(self) -> Signature:
        from api_app.engines_manager.tasks import execute_engine

        return execute_engine.signature(
            args=[self.pk],
            kwargs={},
            queue=get_queue_name(settings.CONFIG_QUEUE),
            immutable=True,
            MessageGroupId=str(uuid.uuid4()),
            priority=self.priority,
        )

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
        runner |= self._get_engine_signature()
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
        self.status = self.STATUSES.RUNNING
        self.save(update_fields=["status"])
        runner = self._get_pipeline(
            self.analyzers_to_execute.all(),
            self.pivots_to_execute.all(),
            self.connectors_to_execute.all(),
            self.visualizers_to_execute.all(),
        )
        runner()

    def get_user_events_data_model(self) -> BaseDataModelQuerySet:
        return self.analyzable.get_all_user_events_data_model(self.user)

    def get_analyzers_data_models(self) -> BaseDataModelQuerySet:
        DataModel = self.analyzable.get_data_model_class()  # noqa
        return DataModel.objects.filter(
            pk__in=self.analyzerreports.values_list("data_model_object_id", flat=True)
        )

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
            .exclude(status=cls.STATUSES.FAILED)
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
    """
    Represents a parameter that can be configured for a Python module.

    Attributes:
        name (str): The name of the parameter.
        type (str): The type of the parameter.
        description (str): A brief description of the parameter.
        is_secret (bool): Indicates if the parameter contains sensitive data.
        required (bool): Indicates if the parameter is mandatory.
        python_module (ForeignKey): The Python module associated with the parameter.
    """

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
        """Returns the name of the parameter."""
        return self.name

    def refresh_cache_keys(self):
        """
        Refreshes the cache keys associated with the parameter's configuration class.
        """
        self.config_class.delete_class_cache_keys()
        for config in self.config_class.objects.filter(
            python_module=self.python_module
        ):
            config: PythonConfig
            config.refresh_cache_keys()

    @cached_property
    def config_class(self) -> Type["PythonConfig"]:
        """
        Returns the configuration class associated with the Python module.

        Returns:
            Type[PythonConfig]: The configuration class.
        """
        return self.python_module.python_class.config_model


class PluginConfig(OwnershipAbstractModel):
    """
    Represents a configuration value for a specific parameter in a plugin.

    Attributes:
        value (JSONField): The configuration value in JSON format.
        parameter (ForeignKey): The parameter this configuration is associated with.
        updated_at (DateTimeField): The timestamp of the last update.
        analyzer_config (ForeignKey): The analyzer configuration this config belongs to.
        connector_config (ForeignKey): The connector configuration this config belongs to.
        visualizer_config (ForeignKey): The visualizer configuration this config belongs to.
        ingestor_config (ForeignKey): The ingestor configuration this config belongs to.
        pivot_config (ForeignKey): The pivot configuration this config belongs to.
    """

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
        """
        Returns the PythonConfig instance this PluginConfig is associated with.

        Returns:
            PythonConfig: The associated PythonConfig instance.
        """
        return list(filter(None, self._possible_configs()))[0]

    def refresh_cache_keys(self):
        """
        Refreshes the cache keys associated with the plugin configuration.
        """
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
        """
        Returns a list of possible configurations this PluginConfig can belong to.

        Returns:
            list[PythonConfig]: A list of possible configurations.
        """
        return [
            self.analyzer_config,
            self.connector_config,
            self.visualizer_config,
            self.ingestor_config,
            self.pivot_config,
        ]

    def clean_config(self) -> None:
        """
        Ensures that exactly one configuration type is set for this PluginConfig.
        """
        if len(list(filter(None, self._possible_configs()))) != 1:
            configs = ", ".join(
                [config.name for config in self._possible_configs() if config]
            )
            if not configs:
                raise ValidationError("You must select a plugin configuration")
            raise ValidationError(f"You must have exactly one between {configs}")

    def clean_value(self):
        """
        Validates the configuration value based on the parameter's type.
        """
        from django.forms.fields import JSONString

        if isinstance(self.value, JSONString):
            self.value = str(self.value)
        if type(self.value).__name__ != self.parameter.type:
            raise ValidationError(
                f"Type {type(self.value).__name__} is wrong:"
                f" should be {self.parameter.type}"
            )

    def clean_parameter(self):
        """
        Ensures the parameter's Python module matches the config's Python module.
        """
        if self.config.python_module != self.parameter.python_module:
            raise ValidationError(
                f"Missmatch between config python module {self.config.python_module}"
                f" and parameter python module {self.parameter.python_module}"
            )

    def clean(self):
        """
        Validates the PluginConfig instance before saving.
        """
        super().clean()
        self.clean_value()
        self.clean_for_organization()
        self.clean_config()
        self.clean_parameter()

    @property
    def attribute(self):
        """Returns the name of the parameter."""
        return self.parameter.name

    def is_secret(self):
        """Returns whether the parameter is marked as secret."""
        return self.parameter.is_secret

    @property
    def plugin_name(self):
        """Returns the name of the plugin associated with this configuration."""
        return self.config.name


class OrganizationPluginConfiguration(models.Model):
    """
    Represents the configuration of a plugin for a specific organization.

    Attributes:
        content_type (ForeignKey): The type of content this configuration applies to.
        object_id (int): The ID of the content object this configuration applies to.
        config (GenericForeignKey): The actual configuration object.
        organization (ForeignKey): The organization this configuration is associated with.
        disabled (bool): Indicates if the configuration is disabled.
        disabled_comment (str): A comment explaining why the configuration is disabled.
        rate_limit_timeout (DurationField): The duration for which rate limits apply.
        rate_limit_enable_task (ForeignKey): The task to re-enable the configuration after a rate limit.
    """

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
        """Returns a string representation of the organization plugin configuration."""
        return f"{self.config} ({self.organization})"

    def disable_for_rate_limit(self):
        """
        Disables the configuration for the organization due to rate limits.
        """
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
        """
        Manually disables the configuration for the organization.

        Args:
            user (User): The user who disabled the configuration.
        """
        self.disabled = True
        self.disabled_comment = (
            f"Disabled by user {user.username}"
            f" at {now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        if self.rate_limit_enable_task:
            self.rate_limit_enable_task.delete()
        self.save()

    def enable_manually(self, user: User):
        """
        Manually enables the configuration for the organization.

        Args:
            user (User): The user who enabled the configuration.
        """
        self.disabled_comment += (
            f"\nEnabled back by {user.username}"
            f" at {now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.enable()

    def enable(self):
        """
        Enables the configuration for the organization.
        """
        logger.info(f"Enabling back {self}")
        self.disabled = False
        self.disabled_comment = ""
        self.save()
        if self.rate_limit_enable_task:
            self.rate_limit_enable_task.delete()


class ListCachable(models.Model):
    """
    Abstract model for classes that support caching a list of instances.

    Methods:
        delete_class_cache_keys(user: User): Deletes cached keys for the class.
        python_path: Returns the Python path of the class.
    """

    class Meta:
        abstract = True

    @classmethod
    def delete_class_cache_keys(cls, user: User = None):
        """
        Deletes cache keys associated with the list of instances for the given user.

        Args:
            user (User): The user for whom the cache keys are being deleted.
        """
        base_key = f"{cls.__name__}_{user.username if user else ''}"
        for key in cache.get_where(f"list_{base_key}").keys():
            logger.debug(f"Deleting cache key {key}")
            cache.delete(key)

    @classmethod
    @property
    def python_path(cls) -> str:
        """
        Returns the Python path of the class.

        Returns:
            str: The Python path.
        """
        return f"{cls.__module__}.{cls.__name__}"


class AbstractConfig(ListCachable):
    """
    Abstract model for plugin configurations.

    Attributes:
        name (str): The name of the configuration.
        description (str): A brief description of the configuration.
        disabled (bool): Indicates if the configuration is disabled.
        orgs_configuration (GenericRelation): The organization configurations for this config.
    """

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
        """Returns the name of the configuration."""
        return self.name

    def get_or_create_org_configuration(
        self, organization: Organization
    ) -> OrganizationPluginConfiguration:
        """
        Retrieves or creates the organization-specific configuration.

        Args:
            organization (Organization): The organization for which to get or create the configuration.

        Returns:
            OrganizationPluginConfiguration: The organization-specific configuration.
        """
        try:
            org_configuration = self.orgs_configuration.get(organization=organization)
        except OrganizationPluginConfiguration.DoesNotExist:
            org_configuration = OrganizationPluginConfiguration.objects.create(
                config=self, organization=organization
            )
        return org_configuration

    @classmethod
    def get_content_type(cls) -> ContentType:
        """
        Returns the content type for the configuration.

        Returns:
            ContentType: The content type.
        """
        return ContentType.objects.get(
            model=cls._meta.model_name, app_label=cls._meta.app_label
        )

    @property
    def disabled_in_organizations(self) -> QuerySet:
        """
        Returns a queryset of organizations where this configuration is disabled.

        Returns:
            QuerySet: The organizations with disabled configurations.
        """
        return self.orgs_configuration.filter(disabled=True)

    @classmethod
    @property
    def runtime_configuration_key(cls) -> str:
        """
        Returns the runtime configuration key for the configuration.

        Returns:
            str: The runtime configuration key.
        """
        return f"{cls.__name__.split('Config')[0].lower()}s"

    @classmethod
    @property
    def snake_case_name(cls) -> str:
        """
        Returns the snake_case name of the configuration.

        Returns:
            str: The snake_case name.
        """
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
        """
        Checks if the configuration is enabled for the given user.

        Args:
            user (User): The user to check.

        Returns:
            bool: True if enabled, False otherwise.
        """
        if user.has_membership():
            return (
                not self.disabled
                and not self.orgs_configuration.filter(
                    disabled=True, organization__pk=user.membership.organization_id
                ).exists()
            )
        return not self.disabled


class AbstractReport(models.Model):
    """
    Abstract model for reports generated by plugins.

    Attributes:
        status (str): The status of the report.
        report (JSONField): The actual report data.
        errors (ArrayField): A list of errors encountered during report generation.
        start_time (DateTimeField): The start time of the report generation.
        end_time (DateTimeField): The end time of the report generation.
        task_id (UUIDField): The ID of the Celery task generating the report.
        job (ForeignKey): The job associated with the report.
        parameters (JSONField): The parameters used for generating the report.
        sent_to_bi (bool): Indicates if the report has been sent to business intelligence (BI) systems.
    """

    objects = AbstractReportQuerySet.as_manager()
    # constants
    STATUSES = ReportStatus

    # fields
    status = models.CharField(max_length=50, choices=STATUSES.choices)
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
        """Returns a string representation of the report."""
        return f"{self.__class__.__name__}(job:#{self.job_id}, {self.config.name})"

    @classmethod
    @property
    def config(cls) -> "AbstractConfig":
        """
        Returns the configuration associated with the report.

        Returns:
            AbstractConfig: The configuration class associated with the report.
        """
        raise NotImplementedError()

    @cached_property
    def runtime_configuration(self):
        """
        Returns the runtime configuration for the report.

        Returns:
            dict: The runtime configuration settings.
        """
        return self.job.get_config_runtime_configuration(self.config)

    # properties
    @property
    def user(self) -> User:
        """
        Returns the user associated with the job that generated the report.

        Returns:
            User: The user associated with the job.
        """
        return self.job.user

    @property
    def process_time(self) -> float:
        """
        Returns the total time taken to process the report.

        Returns:
            float: The process time in seconds, rounded to two decimal places.
        """
        secs = (self.end_time - self.start_time).total_seconds()
        return round(secs, 2)

    def get_value(
        self, search_from: typing.Any, fields: typing.List[str]
    ) -> typing.Any:
        if not fields:
            return search_from
        search_keyword = fields.pop(0)
        if isinstance(search_from, list):
            try:
                index = int(search_keyword)
            except ValueError:
                result = []
                errors = []
                for i, obj in enumerate(search_from):
                    # if we are iterating a list, we get all the objects that matches
                    try:
                        res = self.get_value(obj, [search_keyword] + fields)
                        if isinstance(res, list):
                            result.extend(res)
                        else:
                            result.append(res)
                    except KeyError:
                        errors.append(
                            f"Field {search_keyword} not available at position {i}"
                        )
                if result:
                    self.errors.extend(errors)
                else:
                    raise Exception("No object matches")

                return result
            else:
                # a.b.0
                return self.get_value(search_from[index], fields)
        return self.get_value(search_from[search_keyword], fields)


class PythonConfig(AbstractConfig):
    """
    Configuration model for Python-based plugins.

    Attributes:
        soft_time_limit (int): The soft time limit for the plugin's execution.
        routing_key (str): The routing key for the plugin's task queue.
        python_module (ForeignKey): The Python module associated with the plugin.
        health_check_task (OneToOneField): The periodic task for health checks.
        health_check_status (bool): The current health check status of the plugin.
    """

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
        """
        Returns the routing key for the plugin's task queue.

        Returns:
            str: The routing key.
        """
        if self.routing_key not in settings.CELERY_QUEUES:
            logger.warning(
                f"{self.name}: you have no worker for {self.routing_key}."
                f" Using {settings.DEFAULT_QUEUE} queue."
            )
            return settings.DEFAULT_QUEUE
        return self.routing_key

    @property
    def parameters(self) -> ParameterQuerySet:
        """
        Returns the parameters associated with the plugin's configuration.

        Returns:
            ParameterQuerySet: The queryset of parameters.
        """
        return Parameter.objects.filter(python_module=self.python_module)

    @classmethod
    @property
    def report_class(cls) -> Type[AbstractReport]:
        """
        Returns the report class associated with the plugin configuration.

        Returns:
            Type[AbstractReport]: The report class.
        """
        return cls.reports.rel.related_model

    @classmethod
    def get_subclasses(cls) -> typing.List["PythonConfig"]:
        """
        Returns a list of subclasses of PythonConfig.

        Returns:
            list[PythonConfig]: A list of subclasses.
        """
        child_models = [ct.model_class() for ct in ContentType.objects.all()]
        return [
            model
            for model in child_models
            if (model is not None and issubclass(model, cls) and model is not cls)
        ]

    @classmethod
    @property
    def plugin_type(cls) -> str:
        """
        Returns the type of the plugin.

        Returns:
            str: The plugin type.
        """
        # retro compatibility

        raise NotImplementedError()

    def _get_params(self, user: User, runtime_configuration: Dict) -> Dict[str, Any]:
        """
        Returns the configured parameters for the plugin.

        Args:
            user (User): The user for whom the parameters are configured.
            runtime_configuration (Dict): The runtime configuration settings.

        Returns:
            dict: The configured parameters.
        """
        return {
            parameter.name: parameter.value
            for parameter in self.read_configured_params(user, runtime_configuration)
            if not parameter.is_secret
        }

    def generate_empty_report(self, job: Job, task_id: str, status: str):
        """
        Generates an empty report for the plugin.

        Args:
            job (Job): The job associated with the report.
            task_id (str): The ID of the task generating the report.
            status (str): The status of the report.

        Returns:
            AbstractReport: The generated report.
        """
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
        """
        Refreshes the cache keys associated with the plugin configuration.

        Args:
            user (User): The user for whom the cache keys are refreshed (optional).
        """
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
        """
        Returns the serializer class associated with the plugin configuration.

        Returns:
            Type[PythonConfigSerializer]: The serializer class.
        """
        raise NotImplementedError()

    @classmethod
    @property
    def plugin_name(cls) -> str:
        """
        Returns the name of the plugin.

        Returns:
            str: The plugin name.
        """
        return cls.__name__.split("Config")[0]

    @classmethod
    def signature_pipeline_running(cls, job) -> Signature:
        """
        Returns the signature for setting the job status to 'running'.

        Args:
            job (Job): The job for which the status is set.

        Returns:
            Signature: The Celery task signature.
        """
        return cls._signature_pipeline_status(
            job, getattr(Status, f"{cls.plugin_name.upper()}S_RUNNING").value
        )

    @classmethod
    def signature_pipeline_completed(cls, job) -> Signature:
        """
        Returns the signature for setting the job status to 'completed'.

        Args:
            job (Job): The job for which the status is set.

        Returns:
            Signature: The Celery task signature.
        """
        return cls._signature_pipeline_status(
            job, getattr(Status, f"{cls.plugin_name.upper()}S_COMPLETED").value
        )

    @classmethod
    def _signature_pipeline_status(cls, job, status: str) -> Signature:
        """
        Returns the signature for setting the job status.

        Args:
            job (Job): The job for which the status is set.
            status (str): The status to set.

        Returns:
            Signature: The Celery task signature.
        """
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
        """
        Returns the queue name for the plugin's task queue.

        Returns:
            str: The queue name.
        """
        return get_queue_name(self.get_routing_key())

    @property
    def options(self) -> QuerySet:
        """
        Returns the non-secret parameters associated with the plugin.

        Returns:
            QuerySet: The queryset of non-secret parameters.
        """
        return self.parameters.filter(is_secret=False)

    @property
    def secrets(self) -> QuerySet:
        """
        Returns the secret parameters associated with the plugin.

        Returns:
            QuerySet: The queryset of secret parameters.
        """
        return self.parameters.filter(is_secret=True)

    @property
    def required_parameters(self) -> QuerySet:
        """
        Returns the required parameters associated with the plugin.

        Returns:
            QuerySet: The queryset of required parameters.
        """
        return self.parameters.filter(required=True)

    @deprecated("Please use the queryset method `annotate_configured`.")
    def _is_configured(self, user: User = None) -> bool:
        """
        Checks if the plugin configuration is configured.

        Args:
            user (User): The user for whom the configuration is checked (optional).

        Returns:
            bool: True if the configuration is configured, False otherwise.
        """
        pc = self.__class__.objects.filter(pk=self.pk).annotate_configured(user).first()
        return pc.configured

    @classmethod
    @property
    def config_exception(cls):
        """
        Returns the exception class for configuration errors.

        Returns:
            Exception: The exception class.
        """
        raise NotImplementedError()

    def read_configured_params(
        self, user: User = None, config_runtime: Dict = None
    ) -> ParameterQuerySet:
        """
        Reads the configured parameters for the plugin.

        Args:
            user (User): The user for whom the parameters are read.
            config_runtime (Dict): The runtime configuration settings.

        Returns:
            ParameterQuerySet: The queryset of configured parameters.
        """
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
        """
        Generates a periodic task for health checks.

        This method sets up a periodic task that checks the health status
        of the Python module associated with this configuration.
        """
        from intel_owl.tasks import health_check

        if (
            hasattr(self.python_module, "health_check_schedule")
            and self.python_module.health_check_schedule
        ):
            periodic_task = PeriodicTask.objects.update_or_create(
                name__iexact=f"{self.name}HealthCheck{self.__class__.__name__}",
                task=f"{health_check.__module__}.{health_check.__name__}",
                defaults={
                    "name": f"{self.name}HealthCheck{self.__class__.__name__}",
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
