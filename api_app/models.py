# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import logging
import typing
from typing import Optional

from celery import group
from django.conf import settings
from django.contrib.postgres import fields as pg_fields
from django.db import models
from django.db.models import Q, QuerySet
from django.dispatch import receiver
from django.utils import timezone
from django.utils.functional import cached_property

from api_app.core.models import AbstractReport
from api_app.exceptions import AlreadyFailedJobException
from api_app.helpers import get_now
from certego_saas.apps.organization.membership import Membership
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
    label = models.CharField(max_length=50, blank=False, null=False, unique=True)
    color = models.CharField(max_length=7, blank=False, null=False)

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

    analyzers_requested = pg_fields.ArrayField(
        models.CharField(max_length=128), blank=True, default=list
    )
    connectors_requested = pg_fields.ArrayField(
        models.CharField(max_length=128), blank=True, default=list
    )
    playbooks_requested = pg_fields.ArrayField(
        models.CharField(max_length=128), blank=True, default=list
    )
    analyzers_to_execute = pg_fields.ArrayField(
        models.CharField(max_length=128), blank=True, default=list
    )
    connectors_to_execute = pg_fields.ArrayField(
        models.CharField(max_length=128), blank=True, default=list
    )
    playbooks_to_execute = pg_fields.ArrayField(
        models.CharField(max_length=128), blank=True, default=list
    )

    received_request_time = models.DateTimeField(auto_now_add=True)
    finished_analysis_time = models.DateTimeField(blank=True, null=True)
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
        return hashlib.sha256(self.file.read()).hexdigest()

    @cached_property
    def sha1(self) -> str:
        return hashlib.sha1(self.file.read()).hexdigest()

    def job_cleanup(self) -> None:
        logger.info(f"[STARTING] job_cleanup for <-- {self.__repr__()}.")
        status_to_set = self.Status.RUNNING

        try:
            if self.status == self.Status.FAILED:
                raise AlreadyFailedJobException()

            stats = self.get_analyzer_reports_stats()

            logger.info(
                f"[REPORT] {self.__repr__()}, status:{self.status}, reports:{stats}"
            )

            if len(self.analyzers_to_execute) == stats["all"]:
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

        except AlreadyFailedJobException:
            logger.error(
                f"[REPORT] {self.__repr__()}, status: failed. Do not process the report"
            )

        except Exception as e:
            logger.exception(f"job_id: {self.pk}, Error: {e}")
            self.append_error(str(e), save=False)

        finally:
            if not (self.status == self.Status.FAILED and self.finished_analysis_time):
                self.finished_analysis_time = get_now()
            self.status = status_to_set
            self.save(update_fields=["status", "errors", "finished_analysis_time"])

    @property
    def process_time(self) -> Optional[float]:
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
        return self.analyzer_reports.aggregate(
            all=models.Count("status"),
            **aggregators,
        )

    def get_connector_reports_stats(self) -> dict:
        aggregators = {
            s.lower(): models.Count("status", filter=models.Q(status=s))
            for s in AbstractReport.Status.values
        }
        return self.connector_reports.aggregate(
            all=models.Count("status"),
            **aggregators,
        )

    def kill_if_ongoing(self):
        from intel_owl.celery import app as celery_app

        statuses_to_filter = [
            AbstractReport.Status.PENDING,
            AbstractReport.Status.RUNNING,
        ]
        qs = self.analyzer_reports.filter(status__in=statuses_to_filter)
        task_ids_analyzers = list(qs.values_list("task_id", flat=True))
        qs2 = self.connector_reports.filter(status__in=statuses_to_filter)

        task_ids_connectors = list(qs2.values_list("task_id", flat=True))
        # kill celery tasks using task ids
        celery_app.control.revoke(
            task_ids_analyzers + task_ids_connectors, terminate=True
        )

        # update report statuses
        qs.update(status=self.Status.KILLED)
        # set job status
        self.update_status("killed")

    def _merge_runtime_configuration(
        self,
        runtime_configuration: typing.Dict,
        analyzers: typing.List[str],
        connectors: typing.List[str],
    ):
        # in case of key conflict, runtime_configuration
        # is overwritten by the Plugin configuration
        final_config = {}
        user = self.user
        for analyzer in analyzers:
            # Appending custom config to runtime configuration
            config = runtime_configuration.get(analyzer, {})
            config |= PluginConfig.get_as_dict(
                user,
                PluginConfig.PluginType.ANALYZER,
                PluginConfig.ConfigType.PARAMETER,
                plugin_name=analyzer,
            ).get(analyzer, {})

            if config:
                final_config[analyzer] = config
        for connector in connectors:
            config = runtime_configuration.get(connector, {})
            config |= PluginConfig.get_as_dict(
                user,
                PluginConfig.PluginType.CONNECTOR,
                PluginConfig.ConfigType.PARAMETER,
                plugin_name=connector,
            ).get(connector, {})

            if config:
                final_config[connector] = config
        logger.debug(f"New value of runtime_configuration: {final_config}")
        return final_config

    def _pipeline_configuration(
        self, runtime_configuration: typing.Dict[str, typing.Any]
    ) -> typing.Tuple[typing.List, typing.List, typing.List, typing.List]:
        from api_app.playbooks_manager.dataclasses import PlaybookConfig

        # case playbooks
        if not runtime_configuration and self.playbooks_to_execute:
            configs = []
            analyzers = []
            connectors = []
            playbooks = self.playbooks_to_execute
            # this must be done because each analyzer on the playbook
            # could be executed with a different configuration
            for playbook in PlaybookConfig.filter(
                names=self.playbooks_to_execute
            ).values():
                playbook: PlaybookConfig
                if not playbook.is_ready_to_use and not settings.STAGE_CI:
                    continue
                configs.append(playbook.analyzers | playbook.connectors)
                analyzers.append(
                    [
                        analyzer
                        for analyzer in playbook.analyzers.keys()
                        if analyzer in self.analyzers_to_execute
                    ]
                )
                connectors.append(
                    [
                        connector
                        for connector in playbook.connectors.keys()
                        if connector in self.connectors_to_execute
                    ]
                )
        else:
            configs = [runtime_configuration]
            analyzers = [self.analyzers_to_execute]
            connectors = [self.connectors_to_execute]
            playbooks = [""]
        return configs, analyzers, connectors, playbooks

    def pipeline(self, runtime_configuration: typing.Dict[str, typing.Any]):
        from api_app.analyzers_manager.dataclasses import AnalyzerConfig
        from api_app.connectors_manager.dataclasses import ConnectorConfig
        from intel_owl import tasks
        from intel_owl.consts import DEFAULT_QUEUE

        final_analyzer_signatures = []
        final_connector_signatures = []
        for config, analyzers, connectors, playbook in zip(
            *self._pipeline_configuration(runtime_configuration)
        ):
            config = self._merge_runtime_configuration(config, analyzers, connectors)
            logger.info(
                f"Config is {config},"
                f" analyzers are {analyzers} and"
                f" connectors are {connectors}"
            )
            analyzer_signatures, _ = AnalyzerConfig.stack(
                job_id=self.pk,
                plugins_to_execute=analyzers,
                runtime_configuration=config,
                parent_playbook=playbook,
            )
            for signature in analyzer_signatures:
                if signature not in final_analyzer_signatures:
                    final_analyzer_signatures.append(signature)
                else:
                    logger.warning(f"Signature {signature} is duplicate")

            connector_signatures, _ = ConnectorConfig.stack(
                job_id=self.pk,
                plugins_to_execute=connectors,
                runtime_configuration=config,
                parent_playbook=playbook,
            )
            for signature in connector_signatures:
                if signature not in final_connector_signatures:
                    final_connector_signatures.append(signature)
                else:
                    logger.warning(f"Signature {signature} is duplicate")
        logger.info(f"Analyzer signatures are {final_analyzer_signatures}")
        logger.info(f"Connector signatures are {final_connector_signatures}")
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
    def visible_for_user(cls, user: User) -> QuerySet:
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

    @classmethod
    def get_as_dict(cls, user, entity_type, config_type=None, plugin_name=None) -> dict:
        """
        Returns custom config as dict
        """

        kwargs = {}
        if config_type:
            kwargs["config_type"] = config_type
        custom_configs = cls.visible_for_user(user)
        custom_configs = custom_configs.filter(type=entity_type, **kwargs)
        if plugin_name is not None:
            custom_configs = custom_configs.filter(plugin_name=plugin_name)

        result = {}
        for custom_config in custom_configs:
            custom_config: PluginConfig
            if custom_config.plugin_name not in result:
                result[custom_config.plugin_name] = {}

            # This `if` condition ensures that only a user-level config
            # overrides an organization-level config.
            if (
                custom_config.attribute not in result[custom_config.plugin_name]
                or custom_config.organization is None
            ):
                result[custom_config.plugin_name][
                    custom_config.attribute
                ] = custom_config.value

        logger.debug(f"Final CustomConfig: {result}")

        return result

    @classmethod
    def apply(cls, initial_config, user, plugin_type):
        custom_configs = PluginConfig.get_as_dict(user, plugin_type)
        for plugin in initial_config.values():
            if plugin["name"] in custom_configs:
                for param in plugin["params"]:
                    if param in custom_configs[plugin["name"]]:
                        plugin["params"][param]["value"] = custom_configs[
                            plugin["name"]
                        ][param]


class OrganizationPluginState(models.Model):
    type = models.CharField(choices=PluginConfig.PluginType.choices, max_length=2)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="+",
    )
    plugin_name = models.CharField(max_length=128)
    updated_at = models.DateTimeField(auto_now=True)
    disabled = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["type", "plugin_name", "organization"],
                name="unique_enabled_plugin_entry",
            )
        ]

        indexes = [
            models.Index(
                fields=["organization", "type"],
            ),
        ]

    @classmethod
    def apply(cls, initial_config, user, plugin_type):
        if not user.has_membership():
            return
        custom_configs = OrganizationPluginState.objects.filter(
            organization=user.membership.organization, type=plugin_type
        )
        for plugin in initial_config.values():
            if custom_configs.filter(plugin_name=plugin["name"]).exists():
                plugin["disabled"] = custom_configs.get(
                    plugin_name=plugin["name"]
                ).disabled
