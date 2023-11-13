import io
import json
import logging
from typing import TYPE_CHECKING, Any, Generator, Iterable, Optional, Union

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.functional import cached_property
from django_celery_beat.models import CrontabSchedule, PeriodicTask

from certego_saas.apps.organization.organization import Organization

if TYPE_CHECKING:
    from api_app.playbooks_manager.models import PlaybookConfig
    from api_app.models import Job

from django.core.files import File
from django.http import QueryDict

from certego_saas.apps.user.models import User

logger = logging.getLogger(__name__)


class CreateJobsFromPlaybookInterface:
    playbook_to_execute: "PlaybookConfig"
    name: str

    def _get_serializer(self, value: Any, tlp: str, user: User):
        values = value if isinstance(value, (list, Generator)) else [value]
        if self.playbook_to_execute.is_sample():
            return self._get_file_serializer(values, tlp, user)
        else:
            return self._get_observable_serializer(values, tlp, user)

    def _get_observable_serializer(self, values: Iterable[Any], tlp: str, user: User):
        from api_app.serializers import ObservableAnalysisSerializer
        from tests.mock_utils import MockUpRequest

        return ObservableAnalysisSerializer(
            data={
                "playbooks_requested": [self.playbook_to_execute.pk],
                "observables": [(None, value) for value in values],
                "tlp": tlp,
            },
            context={"request": MockUpRequest(user=user)},
            many=True,
        )

    def _get_file_serializer(
        self, values: Iterable[Union[bytes, File]], tlp: str, user: User
    ):
        from api_app.serializers import FileAnalysisSerializer
        from tests.mock_utils import MockUpRequest

        files = [
            data
            if isinstance(data, File)
            else File(io.BytesIO(data), name=f"{self.name}.{i}")
            for i, data in enumerate(values)
        ]
        query_dict = QueryDict(mutable=True)
        data = {
            "playbooks_requested": self.playbook_to_execute.pk,
            "tlp": tlp,
        }
        query_dict.update(data)
        query_dict.setlist("files", files)
        return FileAnalysisSerializer(
            data=query_dict,
            context={"request": MockUpRequest(user=user)},
            many=True,
        )

    def create_jobs(
        self, value: Any, tlp: str, user: User, send_task: bool = True
    ) -> Generator["Job", None, None]:
        try:
            serializer = self._get_serializer(value, tlp, user)
        except ValueError as e:
            logger.exception(e)
            raise
        else:
            serializer.is_valid(raise_exception=True)
            yield from serializer.save(send_task=send_task)


class OwnershipAbstractModel(models.Model):
    for_organization = models.BooleanField(default=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="+",
        null=True,
        blank=True,
    )

    class Meta:
        indexes = [
            models.Index(
                fields=[
                    "owner",
                    "for_organization",
                ]
            )
        ]
        abstract = True

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

    @cached_property
    def organization(self) -> Optional[Organization]:
        if self.for_organization:
            return self.owner.membership.organization
        return None


class UpdateAbstractModel(models.Model):
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
    name: str
    queue: str
    disabled: bool
    python_module_id: str

    class Meta:
        abstract = True

    def generate_update_periodic_task(self):
        from intel_owl.tasks import update

        if hasattr(self, "update_schedule") and self.update_schedule:
            periodic_task = PeriodicTask.objects.update_or_create(
                name=f"{self.name.title()}Update{self.__class__.__name__}",
                task=f"{update.__module__}.{update.__name__}",
                defaults={
                    "crontab": self.update_schedule,
                    "queue": self.queue,
                    "enabled": not self.disabled and settings.REPO_DOWNLOADER_ENABLED,
                    "kwargs": json.dumps({"python_module_pk": self.python_module_id}),
                },
            )[0]
            self.update_task = periodic_task


class HealthCheckAbstractModel(models.Model):
    health_check_schedule = models.ForeignKey(
        CrontabSchedule,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="healthcheck_for_%(class)s",
    )
    health_check_task = models.OneToOneField(
        PeriodicTask,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="healthcheck_for_%(class)s",
        editable=False,
    )
    name: str
    queue: str
    disabled: bool
    python_module_id: str

    class Meta:
        abstract = True

    def generate_health_check_periodic_task(self):
        from intel_owl.tasks import update

        if hasattr(self, "health_check_schedule") and self.health_check_schedule:
            periodic_task = PeriodicTask.objects.update_or_create(
                name=f"{self.name.title()}HealthCheck{self.__class__.__name__}",
                task=f"{update.__module__}.{update.__name__}",
                defaults={
                    "crontab": self.health_check_schedule,
                    "queue": self.queue,
                    "enabled": not self.disabled and settings.REPO_DOWNLOADER_ENABLED,
                    "kwargs": json.dumps(
                        {
                            "python_module_pk": self.python_module_id,
                            "plugin_config_pk": self.pk,
                        }
                    ),
                },
            )[0]
            self.health_check_task = periodic_task
