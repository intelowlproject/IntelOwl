import io
import logging
from typing import TYPE_CHECKING, Any, Generator, Iterable, Optional, Union

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.functional import cached_property

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
    playbook_to_execute_id: str
    name: str

    def validate_playbook_to_execute(self, user: User):
        from api_app.playbooks_manager.models import PlaybookConfig

        if (
            not PlaybookConfig.objects.filter(pk=self.playbook_to_execute_id)
            .visible_for_user(user)
            .exists()
        ):
            raise RuntimeError(
                f"User {user.username} do not have visibility to"
                f" playbook {self.playbook_to_execute_id}"
            )

    def _get_serializer(self, value: Any, tlp: str, user: User):
        values = value if isinstance(value, (list, Generator)) else [value]
        if self.playbook_to_execute.is_sample():
            return self._get_file_serializer(values, tlp, user)
        else:
            return self._get_observable_serializer(values, tlp, user)

    def _get_observable_serializer(self, values: Iterable[Any], tlp: str, user: User):
        from api_app.serializers.job import ObservableAnalysisSerializer
        from tests.mock_utils import MockUpRequest

        return ObservableAnalysisSerializer(
            data={
                "playbook_requested": self.playbook_to_execute.name,
                "observables": [(None, value) for value in values],
                "tlp": tlp,
            },
            context={"request": MockUpRequest(user=user)},
            many=True,
        )

    def _get_file_serializer(
        self, values: Iterable[Union[bytes, File]], tlp: str, user: User
    ):
        from api_app.serializers.job import FileJobSerializer
        from tests.mock_utils import MockUpRequest

        files = [
            data
            if isinstance(data, File)
            else File(io.BytesIO(data), name=f"{self.name}.{i}")
            for i, data in enumerate(values)
        ]
        query_dict = QueryDict(mutable=True)
        data = {
            "playbook_requested": self.playbook_to_execute.name,
            "tlp": tlp,
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
        send_task: bool = True,
        parent_job=None,
    ) -> Generator["Job", None, None]:
        try:
            serializer = self._get_serializer(value, tlp, user)
        except ValueError as e:
            logger.exception(e)
            raise
        else:
            serializer.is_valid(raise_exception=True)
            yield from serializer.save(send_task=send_task, parent=parent_job)


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
