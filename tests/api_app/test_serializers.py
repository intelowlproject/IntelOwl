from django.conf import settings
from django.core.files import File
from django.http.request import MultiValueDict, QueryDict
from django.test import TransactionTestCase
from rest_framework.exceptions import ValidationError

from api_app.serializers import (
    PlaybookFileAnalysisSerializer,
    PlaybookObservableAnalysisSerializer,
)

PLAYBOOK = "FREE_TO_USE_ANALYZERS"


class PlaybookObservableAnalysisSerializerTestCase(TransactionTestCase):

    IP = "1.1.1.1"

    def test_save(self):

        data = {
            "observables": [["ip", self.IP]],
            "playbooks_requested": [PLAYBOOK],
        }

        serializer = PlaybookObservableAnalysisSerializer(data=data, many=True)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            self.fail(e)

        jobs = serializer.save()
        self.assertEqual(1, len(jobs))
        job = jobs[0]
        self.assertEqual(job.playbooks_to_execute, [PLAYBOOK])


class PlaybookFileAnalysisSerializerTestCase(TransactionTestCase):
    FILE = "file.exe"

    def _read_file_save_job(self, filename: str):
        test_file = f"{settings.PROJECT_LOCATION}/test_files/{filename}"
        self.f = open(test_file, "rb")
        return File(self.f)

    def test_save(self):
        file = self._read_file_save_job(filename=self.FILE)

        data = {
            "files": [file],
            "file_names": [self.FILE],
            "playbooks_requested": [PLAYBOOK],
        }
        qdict = QueryDict("", mutable=True)
        qdict.update(MultiValueDict(data))

        serializer = PlaybookFileAnalysisSerializer(data=qdict, many=True)
        serializer.is_valid(raise_exception=True)
        jobs = serializer.save()
        self.assertEqual(1, len(jobs))
        job = jobs[0]
        self.assertEqual(job.playbooks_to_execute, [PLAYBOOK])
