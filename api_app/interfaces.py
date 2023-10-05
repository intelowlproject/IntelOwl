import io
import logging
from typing import TYPE_CHECKING, Any, Generator, Iterable, Union

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
