import abc
import io
import logging
from typing import Any, Generator

from django.core.files import File
from django.http import QueryDict

from api_app.models import AbstractReport, Job
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.user.models import User

logger = logging.getLogger(__name__)


class CreateJobsFromPlaybookInterface:

    playbook_to_execute: PlaybookConfig

    @abc.abstractmethod
    def get_values(self, report: AbstractReport) -> Generator[Any, None, None]:
        ...

    def _get_serializer(self, report: AbstractReport, tlp: str, user: User):

        values = self.get_values(report)
        if self.playbook_to_execute.is_sample():
            return self._get_file_serializer(values, tlp, user)
        else:
            return self._get_observable_serializer(values, tlp, user)

    def _get_observable_serializer(
        self, values: Generator[Any, None, None], tlp: str, user: User
    ):
        from api_app.serializers import ObservableAnalysisSerializer
        from tests.mock_utils import MockUpRequest

        return ObservableAnalysisSerializer(
            data={
                "playbooks_requested": [self.playbook_to_execute.pk],
                "observables": [(None, value) for value in values],
                "send_task": True,
                "tlp": tlp,
            },
            context={"request": MockUpRequest(user=user)},
            many=True,
        )

    def _get_file_serializer(
        self, values: Generator[bytes, None, None], tlp: str, user: User
    ):
        from api_app.serializers import FileAnalysisSerializer
        from tests.mock_utils import MockUpRequest

        files = [
            File(io.BytesIO(data), name=f"{self.__class__.__name__}.{i}")
            for i, data in enumerate(values)
        ]
        query_dict = QueryDict(mutable=True)
        data = {
            "playbooks_requested": self.playbook_to_execute.pk,
            "send_task": True,
            "tlp": tlp,
        }
        query_dict.update(data)
        query_dict.setlist("files", files)
        return FileAnalysisSerializer(
            data=query_dict,
            context={"request": MockUpRequest(user=user)},
            many=True,
        )

    def _create_jobs(
        self, report: AbstractReport, tlp: str, user: User, send_task: bool = True
    ) -> Generator[Job, None, None]:

        try:
            serializer = self._get_serializer(report, tlp, user)
        except ValueError as e:
            logger.exception(e)
            raise
        else:
            serializer.is_valid(raise_exception=True)
            yield from serializer.save(send_task=send_task)
