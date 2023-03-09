# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import typing
from itertools import chain
from typing import Optional

from celery import group
from django.conf import settings
from django.contrib.postgres import fields as pg_fields
from django.core.validators import MinLengthValidator, RegexValidator
from django.db import models
from django.db.models import Q, QuerySet
from django.dispatch import receiver
from django.utils import timezone
from django.utils.functional import cached_property

from api_app.core.models import AbstractConfig, AbstractReport
from api_app.helpers import calculate_sha1, calculate_sha256, get_now
from certego_saas.apps.organization.organization import Organization
from certego_saas.models import User

logger = logging.getLogger(__name__)


def file_directory_path(instance, filename):
    now = timezone.now().strftime("%Y_%m_%d_%H_%M_%S")
    return f"job_{now}_{filename}"


class Status(models.TextChoices):
    PENDING = "pending", "pending"
    RUNNING = "running", "running"
    REPORTED_WITHOUT_FAILS = "reported_without_fails", "reported_without_fails"
    REPORTED_WITH_FAILS = "reported_with_fails", "reported_with_fails"
    KILLED = "killed", "killed"
    FAILED = "failed", "failed"

    @classmethod
    def final_statuses(cls) -> typing.List["Status"]:
        return [
            cls.REPORTED_WITHOUT_FAILS,
            cls.REPORTED_WITH_FAILS,
            cls.KILLED,
            cls.FAILED,
        ]


class Position(models.TextChoices):
    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"


class TLP(models.TextChoices):
    WHITE = "WHITE"
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"

    @classmethod
    def get_priority(cls, tlp):
        order = {
            cls.WHITE: 0,
            cls.GREEN: 1,
            cls.AMBER: 2,
            cls.RED: 3,
        }
        return order.get(tlp, None)


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


class ObservableClassification(models.TextChoices):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    HASH = "hash"
    GENERIC = "generic"
    EMPTY = ""


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
    playbooks_requested = models.ManyToManyField(
        "playbooks_manager.PlaybookConfig", related_name="requested_in_jobs", blank=True
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
    playbooks_to_execute = models.ManyToManyField(
        "playbooks_manager.PlaybookConfig", related_name="executed_in_jobs", blank=True
    )

    received_request_time = models.DateTimeField(auto_now_add=True, db_index=True)
    finished_analysis_time = models.DateTimeField(blank=True, null=True)
    process_time = models.FloatField(blank=True, null=True)
    tlp = models.CharField(max_length=8, choices=TLP.choices, default=TLP.WHITE)
    errors = pg_fields.ArrayField(
        models.CharField(max_length=900), blank=True, default=list, null=True
    )
    file = models.FileField(blank=True, upload_to=file_directory_path)
    tags = models.ManyToManyField(Tag, related_name="jobs", blank=True)

    def __str__(self):
        if self.is_sample:
            return f'Job(#{self.pk}, "{self.file_name}")'
        return f'Job(#{self.pk}, "{self.observable_name}")'

    @cached_property
    def sha256(self) -> str:
        return calculate_sha256(self.file.read())

    @cached_property
    def sha1(self) -> str:
        return calculate_sha1(self.file.read())

    def job_cleanup(self) -> None:
        logger.info(f"[STARTING] job_cleanup for <-- {self.__repr__()}.")
        status_to_set = self.Status.RUNNING

        try:
            if self.status == self.Status.FAILED:
                logger.error(
                    f"[REPORT] {self.__repr__()}, status: failed. "
                    "Do not process the report"
                )
            else:
                stats = self.get_analyzer_reports_stats()

                logger.info(
                    f"[REPORT] {self.__repr__()}, status:{self.status}, reports:{stats}"
                )

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

    def _merge_runtime_configuration(
        self,
        runtime_configuration: typing.Dict,
        analyzers: QuerySet,
        connectors: QuerySet,
    ):
        logger.debug(f"Starting runtime_configuration: {runtime_configuration}")

        final_config = {}
        user = self.user
        for plugin in list(chain(analyzers, connectors)):
            plugin: AbstractConfig
            # in case of key conflict, Plugin configuration
            # is overwritten by the runtime_configuration
            config = plugin.read_params(user)
            config |= runtime_configuration.get(plugin.name, {})
            final_config[plugin.name] = config
        logger.debug(f"New value of runtime_configuration: {final_config}")
        return final_config

    def _pipeline_configuration(
        self, runtime_configuration: typing.Dict[str, typing.Any]
    ) -> typing.Tuple[
        typing.List[QuerySet],
        typing.List[QuerySet],
        typing.List[QuerySet],
        typing.List[QuerySet],
        range,
    ]:

        visualizers = [self.visualizers_to_execute.all()]
        if not self.playbooks_to_execute.all().exists():
            configs = [runtime_configuration]
            analyzers = [self.analyzers_to_execute.all()]
            connectors = [self.connectors_to_execute.all()]
        else:
            # case playbooks
            configs = []
            analyzers = []
            connectors = []
            # this must be done because each analyzer on the playbook
            # could be executed with a different configuration
            for playbook in self.playbooks_to_execute.all():
                configs.append(
                    playbook.runtime_configuration["analyzers"]
                    | playbook.runtime_configuration["connectors"]
                )
                analyzers.append(
                    self.analyzers_to_execute.intersection(playbook.analyzers.all())
                )
                connectors.append(
                    self.connectors_to_execute.intersection(playbook.connectors.all())
                )

        return configs, analyzers, connectors, visualizers, range(len(configs))

    def pipeline(self, runtime_configuration: typing.Dict[str, typing.Any]):
        from intel_owl import tasks
        from intel_owl.celery import DEFAULT_QUEUE

        final_analyzer_signatures = []
        final_connector_signatures = []
        final_visualizer_signatures = []
        for config, analyzers, connectors, visualizers, i in zip(
            *self._pipeline_configuration(runtime_configuration)
        ):
            config = self._merge_runtime_configuration(config, analyzers, connectors)
            logger.info(
                f"Config is {config},"
                f" analyzers are {analyzers} "
                f" connectors are {connectors} "
                f" visualizers are {visualizers} "
            )

            for final_signatures, plugins in zip(
                (
                    final_analyzer_signatures,
                    final_connector_signatures,
                    final_visualizer_signatures,
                ),
                (analyzers, connectors, visualizers),
            ):
                try:
                    playbook = self.playbooks_to_execute.all()[i].pk
                except IndexError:
                    playbook = None
                config_class: typing.Type[AbstractConfig]
                for plugin in plugins:
                    try:
                        signature = plugin.get_signature(
                            self.pk,
                            config.get(plugin.name, {}),
                            playbook,
                        )
                    except RuntimeError:
                        self.append_error(f"Plugin {plugin.name} is not ready")
                    else:
                        if signature not in final_signatures:
                            final_signatures.append(signature)

        logger.info(f"Analyzer signatures are {final_analyzer_signatures}")
        logger.info(f"Connector signatures are {final_connector_signatures}")
        logger.info(f"Visualizer signatures are {final_connector_signatures}")
        self.update_status(Job.Status.RUNNING)
        runner = (
            group(final_analyzer_signatures)
            | tasks.continue_job_pipeline.signature(
                args=[self.pk],
                kwargs={},
                queue=DEFAULT_QUEUE,
                soft_time_limit=10,
                immutable=True,
            )
            | group(final_connector_signatures)
            | group(final_visualizer_signatures)
        )
        runner()

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
        for config in AbstractConfig.__subclasses__():
            if self.type == config._get_type():
                return config.objects.get(name=self.plugin_name)
        raise TypeError("Unable to find configuration")
