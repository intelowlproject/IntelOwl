import datetime
import io
import logging
from typing import TYPE_CHECKING, Any, Generator, Iterable, Optional, Union

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import QuerySet
from django.utils.functional import cached_property

from certego_saas.apps.organization.organization import Organization

if TYPE_CHECKING:
    from api_app.models import Job
    from api_app.playbooks_manager.models import PlaybookConfig

from django.core.files import File
from django.http import QueryDict

from certego_saas.apps.user.models import User

logger = logging.getLogger(__name__)


class CreateJobsFromPlaybookInterface:
    """
    Interface for creating jobs from playbooks.

    Attributes:
        playbooks_choice (QuerySet): The queryset of selected playbooks.
        name (str): The name of the job.
        delay (datetime.timedelta): The delay before the job is executed.
    """

    playbooks_choice: QuerySet
    name: str
    delay: datetime.timedelta

    @property
    def playbooks_names(self):
        """Returns a comma-separated string of playbook names."""
        return ", ".join(self.playbooks_choice.values_list("name", flat=True))

    def validate_playbooks(self, user: User):
        """
        Validates that the user has visibility to the selected playbooks.

        Args:
            user (User): The user to validate playbooks for.

        Raises:
            RuntimeError: If the user does not have visibility to any of the playbooks.
        """
        from api_app.playbooks_manager.models import PlaybookConfig

        for playbook in self.playbooks_choice.all():
            if not PlaybookConfig.objects.filter(pk=playbook.pk).visible_for_user(user).exists():
                raise RuntimeError(f"User {user.username} do not have visibility to playbook {playbook.pk}")

    def _get_serializer(
        self,
        value: Any,
        tlp: str,
        user: User,
        delay: datetime.timedelta,
        playbook_to_execute: "PlaybookConfig",
    ):
        """
        Gets the appropriate serializer based on the playbook type.

        Args:
            value (Any): The value to be serialized.
            tlp (str): The TLP level.
            user (User): The user executing the playbook.
            delay (datetime.timedelta): The delay before the job is executed.
            playbook_to_execute (PlaybookConfig): The playbook to execute.

        Returns:
            Serializer: The appropriate serializer instance.
        """
        values = value if isinstance(value, (list, Generator)) else [value]
        if playbook_to_execute.is_sample():
            return self._get_file_serializer(
                values, tlp, user, delay=delay, playbook_to_execute=playbook_to_execute
            )
        else:
            return self._get_observable_serializer(
                values, tlp, user, playbook_to_execute=playbook_to_execute, delay=delay
            )

    @staticmethod
    def _get_observable_serializer(
        values: Iterable[Any],
        tlp: str,
        user: User,
        playbook_to_execute: "PlaybookConfig",
        delay: datetime.timedelta = datetime.timedelta(),
    ):
        """
        Gets the serializer for observable analysis.

        Args:
            values (Iterable[Any]): The values to be serialized.
            tlp (str): The TLP level.
            user (User): The user executing the playbook.
            playbook_to_execute (PlaybookConfig): The playbook to execute.
            delay (datetime.timedelta): The delay before the job is executed.

        Returns:
            ObservableAnalysisSerializer: The serializer instance for observable analysis.
        """
        from api_app.serializers.job import ObservableAnalysisSerializer
        from tests.mock_utils import MockUpRequest

        return ObservableAnalysisSerializer(
            data={
                "playbook_requested": playbook_to_execute.name,
                "observables": [(None, value) for value in values],  # (classification, value)
                # -> the classification=None it's just a placeholder
                #    because it'll be calculated later
                "tlp": tlp,
                "delay": int(delay.total_seconds()),  # datetime.timedelta serialization
            },
            context={"request": MockUpRequest(user=user)},
            many=True,
        )

    def _get_file_serializer(
        self,
        values: Iterable[Union[bytes, File]],
        tlp: str,
        user: User,
        playbook_to_execute: "PlaybookConfig",
        delay: datetime.timedelta = datetime.timedelta(),
    ):
        """
        Gets the serializer for file analysis.

        Args:
            values (Iterable[Union[bytes, File]]): The values to be serialized.
            tlp (str): The TLP level.
            user (User): The user executing the playbook.
            playbook_to_execute (PlaybookConfig): The playbook to execute.
            delay (datetime.timedelta): The delay before the job is executed.

        Returns:
            FileJobSerializer: The serializer instance for file analysis.
        """
        from api_app.serializers.job import FileJobSerializer
        from tests.mock_utils import MockUpRequest

        files = [
            (data if isinstance(data, File) else File(io.BytesIO(data), name=f"{self.name}.{i}"))
            for i, data in enumerate(values)
        ]
        query_dict = QueryDict(mutable=True)
        data = {
            "playbook_requested": playbook_to_execute.name,
            "tlp": tlp,
            "delay": int(delay.total_seconds()),  # datetime.timedelta serialization
        }
        query_dict.update(data)
        query_dict.setlist("files", files)
        return FileJobSerializer(
            data=query_dict,
            context={"request": MockUpRequest(user=user)},
            many=True,
        )

    def create_jobs(
        self,
        value: Any,
        tlp: str,
        user: User,
        playbook_to_execute: "PlaybookConfig",
        delay: datetime.timedelta = datetime.timedelta(),
        send_task: bool = True,
        parent_job=None,
    ) -> Generator["Job", None, None]:
        """
        Creates jobs from the given playbook configuration.

        Args:
            value (Any): The value to be serialized.
            tlp (str): The TLP level.
            user (User): The user executing the playbook.
            playbook_to_execute (PlaybookConfig): The playbook to execute.
            delay (datetime.timedelta): The delay before the job is executed.
            send_task (bool): Whether to send the task.
            parent_job (Optional[Job]): The parent job, if any.

        Yields:
            Job: The created job instances.

        Raises:
            ValueError: If the serializer is invalid.
        """
        try:
            serializer = self._get_serializer(
                value, tlp, user, delay, playbook_to_execute=playbook_to_execute
            )
        except ValueError as e:
            logger.exception(e)
            raise
        else:
            serializer.is_valid(raise_exception=True)
            yield from serializer.save(send_task=send_task, parent=parent_job)


class OwnershipAbstractModel(models.Model):
    """
    Abstract model that provides ownership functionality.

    Attributes:
        for_organization (bool): Whether the model is for an organization.
        owner (ForeignKey): The owner of the model, linked to the user.
    """

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
        """
        Validates the `for_organization` field.

        Raises:
            ValidationError: If `for_organization` is set without an owner, or if the owner does not have an organization.
        """
        if self.for_organization and not self.owner:
            raise ValidationError("You can't set `for_organization` and not have an owner")
        if self.for_organization and not self.owner.has_membership():
            raise ValidationError(
                f"You can't create `for_organization` {self.__class__.__name__}"
                " if you do not have an organization"
            )

    @cached_property
    def organization(self) -> Optional[Organization]:
        """
        Returns the organization associated with the owner, if any.

        Returns:
            Optional[Organization]: The organization associated with the owner, or None if not applicable.
        """
        if self.for_organization:
            return self.owner.membership.organization
        return None
