# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import logging
from typing import Optional

from django.conf import settings
from django.contrib.postgres import fields as pg_fields
from django.db import models
from django.dispatch import receiver
from django.utils import timezone
from django.utils.functional import cached_property

from api_app.core.models import Status as ReportStatus
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
    observable_classification = models.CharField(max_length=12, blank=True)
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
    analyzers_to_execute = pg_fields.ArrayField(
        models.CharField(max_length=128), blank=True, default=list
    )
    connectors_to_execute = pg_fields.ArrayField(
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
            for s in ReportStatus.values
        }
        return self.analyzer_reports.aggregate(
            all=models.Count("status"),
            **aggregators,
        )

    def get_connector_reports_stats(self) -> dict:
        aggregators = {
            s.lower(): models.Count("status", filter=models.Q(status=s))
            for s in ReportStatus.values
        }
        return self.connector_reports.aggregate(
            all=models.Count("status"),
            **aggregators,
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


@receiver(models.signals.pre_delete, sender=Job)
def delete_file(sender, instance: Job, **kwargs):
    if instance.file:
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
                fields=["type", "attribute", "organization", "owner"],
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
    def get_as_dict(cls, user, entity_type, plugin_name=None) -> dict:
        """
        Returns custom config as dict
        """
        custom_configs = cls.objects.none()

        # Since, user-level custom configs should override organization-level configs,
        # we need to get the organization-level configs, if any, first.
        try:
            membership = Membership.objects.get(user=user)
            custom_configs |= cls.objects.filter(
                organization=membership.organization,
                type=entity_type,
            )
        except Membership.DoesNotExist:
            # If user is not a member of any organization, we don't need to do anything.
            pass

        custom_configs |= cls.objects.filter(
            type=entity_type,
            owner=user,
        )
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
