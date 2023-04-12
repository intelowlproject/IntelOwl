# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import base64
import logging
import typing
from typing import Optional

from celery import group
from django.conf import settings
from django.contrib.postgres import fields as pg_fields
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator, RegexValidator
from django.db import models
from django.db.models import Q, QuerySet
from django.dispatch import receiver
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property

from api_app.choices import TLP, ObservableClassification, Status
from api_app.core.models import AbstractConfig, AbstractReport
from api_app.helpers import calculate_sha1, calculate_sha256, get_now
from api_app.validators import validate_runtime_configuration
from certego_saas.apps.organization.organization import Organization
from certego_saas.models import User
from intel_owl import tasks
from intel_owl.celery import DEFAULT_QUEUE, get_queue_name

logger = logging.getLogger(__name__)


def file_directory_path(instance, filename):
    now = timezone.now().strftime("%Y_%m_%d_%H_%M_%S")
    return f"job_{now}_{filename}"


def default_runtime():
    return {
        "analyzers": {},
        "connectors": {},
        "visualizers": {},
    }


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
    class Meta:
        indexes = [
            models.Index(
                fields=[
                    "md5",
                    "status",
                ]
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

    def __str__(self):
        return f'{self.__class__.__name__}(#{self.pk}, "{self.analyzed_object_name}")'

    @property
    def analyzed_object_name(self):
        return self.file_name if self.is_sample else self.observable_name

    @cached_property
    def sha256(self) -> str:
        return calculate_sha256(self.file.read())

    @cached_property
    def sha1(self) -> str:
        return calculate_sha1(self.file.read())

    @cached_property
    def b64(self) -> str:
        return base64.b64encode(self.file.read()).decode("utf-8")

    def get_absolute_url(self):
        return reverse("jobs-detail", args=[self.pk])

    @property
    def url(self):
        return settings.WEB_CLIENT_URL + self.get_absolute_url()

    def job_cleanup(self) -> None:
        logger.info(f"[STARTING] job_cleanup for <-- {self}.")
        status_to_set = self.Status.RUNNING

        try:
            if self.status == self.Status.FAILED:
                logger.error(
                    f"[REPORT] {self}, status: failed. " "Do not process the report"
                )
            else:
                stats = self.get_analyzer_reports_stats()

                logger.info(f"[REPORT] {self}, status:{self.status}, reports:{stats}")

                if self.analyzers_to_execute.all().count() == stats["all"]:
                    if stats["running"] > 0 or stats["pending"] > 0:
                        status_to_set = self.Status.RUNNING
                    elif stats["success"] == stats["all"]:
                        status_to_set = self.Status.REPORTED_WITHOUT_FAILS
                    elif stats["failed"] == stats["all"]:
                        status_to_set = self.Status.FAILED
                    elif stats["failed"] >= 1 or stats["killed"] >= 1:
                        status_to_set = self.Status.REPORTED_WITH_FAILS
                    elif stats["killed"] == stats["all"]:
                        status_to_set = self.Status.KILLED

        except Exception as e:
            logger.exception(f"job_id: {self.pk}, Error: {e}")
            self.append_error(str(e), save=False)

        finally:
            if not (self.status == self.Status.FAILED and self.finished_analysis_time):
                self.finished_analysis_time = get_now()
                self.process_time = self.calculate_process_time()
            logger.info(f"{self.__repr__()} setting status to {status_to_set}")
            self.status = status_to_set
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

    def update_status(self, status: str, save=True):
        self.status = status
        if save:
            self.save(update_fields=["status"])

    def append_error(self, err_msg: str, save=True):
        self.errors.append(err_msg)
        if save:
            self.save(update_fields=["errors"])

    def get_analyzer_reports_stats(self) -> dict:
        aggregators = {
            s.lower(): models.Count("status", filter=models.Q(status=s))
            for s in AbstractReport.Status.values
        }
        return self.analyzerreports.aggregate(
            all=models.Count("status"),
            **aggregators,
        )

    def get_connector_reports_stats(self) -> dict:
        aggregators = {
            s.lower(): models.Count("status", filter=models.Q(status=s))
            for s in AbstractReport.Status.values
        }
        return self.connectorreports.aggregate(
            all=models.Count("status"),
            **aggregators,
        )

    def kill_if_ongoing(self):
        from intel_owl.celery import app as celery_app

        statuses_to_filter = [
            AbstractReport.Status.PENDING,
            AbstractReport.Status.RUNNING,
        ]
        qs = self.analyzerreports.filter(status__in=statuses_to_filter)
        task_ids_analyzers = list(qs.values_list("task_id", flat=True))
        qs2 = self.connectorreports.filter(status__in=statuses_to_filter)

        task_ids_connectors = list(qs2.values_list("task_id", flat=True))
        # kill celery tasks using task ids
        celery_app.control.revoke(
            task_ids_analyzers + task_ids_connectors, terminate=True
        )

        # update report statuses
        qs.update(status=self.Status.KILLED)
        # set job status
        self.update_status(self.Status.KILLED)

    def execute(self):
        self.update_status(Job.Status.RUNNING)
        analyzers_signatures = [
            plugin.get_signature(self) for plugin in self.analyzers_to_execute.all()
        ]
        logger.info(f"Analyzer signatures are {analyzers_signatures}")

        connectors_signatures = [
            plugin.get_signature(self) for plugin in self.connectors_to_execute.all()
        ]
        logger.info(f"Connector signatures are {connectors_signatures}")

        visualizers_signatures = [
            plugin.get_signature(self) for plugin in self.visualizers_to_execute.all()
        ]
        logger.info(f"Visualizer signatures are {visualizers_signatures}")

        runner = (
            group(analyzers_signatures)
            | tasks.continue_job_pipeline.signature(
                args=[self.pk],
                kwargs={},
                queue=get_queue_name(DEFAULT_QUEUE),
                soft_time_limit=10,
                immutable=True,
            )
            | group(connectors_signatures)
            | group(visualizers_signatures)
        )
        runner()

    def get_config_runtime_configuration(self, config: AbstractConfig) -> typing.Dict:
        from api_app.analyzers_manager.models import AnalyzerConfig
        from api_app.connectors_manager.models import ConnectorConfig
        from api_app.visualizers_manager.models import VisualizerConfig

        if isinstance(config, AnalyzerConfig):
            key = "analyzers"
            try:
                self.analyzers_to_execute.get(name=config.name)
            except AnalyzerConfig.DoesNotExist:
                raise TypeError(
                    f"Analyzer {config.name} is not configured inside job {self.pk}"
                )
        elif isinstance(config, ConnectorConfig):
            key = "connectors"
            try:
                self.connectors_to_execute.get(name=config.name)
            except ConnectorConfig.DoesNotExist:
                raise TypeError(
                    f"Connector {config.name} is not configured inside job {self.pk}"
                )
        elif isinstance(config, VisualizerConfig):
            key = "visualizers"
            try:
                self.visualizers_to_execute.get(name=config.name)
            except VisualizerConfig.DoesNotExist:
                raise TypeError(
                    f"Visualizer {config.name} is not configured inside job {self.pk}"
                )
        else:
            raise TypeError(f"Config {type(config)} is not supported")
        return self.runtime_configuration[key].get(config.name, {})

    @classmethod
    def visible_for_user(cls, user: User):
        """
        User has access to:
        - jobs with TLP = CLEAR or GREEN
        - jobs with TLP = AMBER or RED and
        created by a member of their organization.
        """
        if user.has_membership():
            user_query = Q(user=user) | Q(
                user__membership__organization_id=user.membership.organization_id
            )
        else:
            user_query = Q(user=user)
        query = Q(tlp__in=[TLP.CLEAR, TLP.GREEN]) | (
            Q(tlp__in=[TLP.AMBER, TLP.RED]) & (user_query)
        )
        return cls.objects.all().filter(query)

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


@receiver(models.signals.pre_delete, sender=Job)
def delete_file(sender, instance: Job, **kwargs):
    if instance.file:
        instance.file.delete()


class PluginConfig(models.Model):
    class PluginType(models.TextChoices):
        ANALYZER = "1", "Analyzer"
        CONNECTOR = "2", "Connector"
        VISUALIZER = "3", "Visualizer"

    class ConfigType(models.TextChoices):
        PARAMETER = "1", "Parameter"
        SECRET = "2", "Secret"

    type = models.CharField(choices=PluginType.choices, max_length=2)
    config_type = models.CharField(choices=ConfigType.choices, max_length=2)
    attribute = models.CharField(max_length=128)
    value = models.JSONField(blank=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="custom_configs",
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="custom_configs",
    )
    plugin_name = models.CharField(max_length=128)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["type", "attribute", "organization", "owner", "plugin_name"],
                name="unique_custom_config_entry",
            )
        ]

        indexes = [
            models.Index(
                fields=["owner", "type"],
            ),
            models.Index(
                fields=["type", "organization"],
            ),
        ]

    @classmethod
    def visible_for_user(cls, user: User = None) -> QuerySet:
        from certego_saas.apps.organization.membership import Membership

        configs = cls.objects.all()
        if user:
            # User-level custom configs should override organization-level configs,
            # we need to get the organization-level configs, if any, first.
            try:
                membership = Membership.objects.get(user=user)
            except Membership.DoesNotExist:
                # If user is not a member of any organization,
                # we don't need to do anything.
                configs = configs.filter(owner=user)
            else:
                configs = configs.filter(
                    Q(organization=membership.organization) | Q(owner=user)
                )

        return configs

    def invalidate_config_verification(self):
        self.config.get_verification.invalidate(self.config)
        if self.organization is not None:
            for membership in self.organization.members.all():
                self.config.get_verification.invalidate(self.config, membership.user)
        else:
            self.config.get_verification.invalidate(self.config, self.owner)

    @cached_property
    def config(self) -> AbstractConfig:
        return self.config_class.objects.get(name=self.plugin_name)

    @cached_property
    def config_class(self) -> typing.Type[AbstractConfig]:

        for config in AbstractConfig.__subclasses__():
            if self.type == config.plugin_type.value:
                return config
        raise TypeError(f"Unable to find configuration for type {self.type}")

    def clean_plugin_name(self):
        try:
            self.config  # noqa
        except TypeError as e:
            raise ValidationError(str(e))
        except AbstractConfig.DoesNotExist:
            raise ValidationError(
                f"Unable to find configuration with name {self.plugin_name}"
            )

    def clean(self) -> None:
        self.clean_plugin_name()
