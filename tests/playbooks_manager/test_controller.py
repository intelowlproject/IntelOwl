import os

from django.conf import settings
from django.core.files import File
from django.http.request import MultiValueDict, QueryDict
from django.test import TransactionTestCase

from api_app.serializers import (
    PlaybookFileAnalysisSerializer,
    PlaybookObservableAnalysisSerializer,
)
from intel_owl.tasks import start_playbooks
from tests import PollingFunction


class PlaybooksScriptObservableTestCase(TransactionTestCase):
    # constants
    TIMEOUT_SECONDS: int = 60 * 5  # 5 minutes
    SLEEP_SECONDS: int = 5  # 5 seconds

    def setUp(self):
        playbook_to_test = os.environ.get("TEST_PLAYBOOK", "")
        self.playbook_to_test = playbook_to_test
        return super().setUp()

    def tearDown(self):
        self.test_job.delete()
        return super().tearDown()

    def test_start_playbooks(self, *args, **kwargs):
        print(
            "\n[START] -----"
            f"{self.__class__.__name__}.test_start_playbooks----"
            f"\nTesting observables"
        )
        TEST_IP = os.environ.get("TEST_IP", "1.1.1.1")

        data = {
            "observables": [["ip", TEST_IP]],
            "playbooks_requested": [self.playbook_to_test],
        }

        serializer = PlaybookObservableAnalysisSerializer(data=data, many=True)
        serializer.is_valid(raise_exception=True)

        validated_data = serializer.validated_data
        [data.pop("runtime_configuration") for data in validated_data]

        self.test_job = serializer.save()[0]

        print(
            f"[REPORT] Job:{self.test_job.pk}, status:'{self.test_job.status}',",
            f"Playbooks: {self.test_job.playbooks_to_execute}",
        )

        start_playbooks(self.test_job.pk, {})

        poll_result = PollingFunction(self, function_name="start_playbooks")
        return poll_result


class PlaybooksScriptFileTestCase(PlaybooksScriptObservableTestCase):
    def _read_file_save_job(self, filename: str):
        test_file = f"{settings.PROJECT_LOCATION}/test_files/{filename}"
        with open(test_file, "rb") as f:
            return File(f)

    def test_start_playbooks(self, *args, **kwargs):
        print("\n[START] -----" f"{self.__class__.__name__}.test_start_playbooks----")

        TEST_FILE = "file.exe"

        file = self._read_file_save_job(filename=TEST_FILE)

        data = {
            "files": [file],
            "file_names": [TEST_FILE],
            "playbooks_requested": [self.playbook_to_test],
        }

        qdict = QueryDict("", mutable=True)
        qdict.update(MultiValueDict(data))

        serializer = PlaybookFileAnalysisSerializer(data=data, many=True)
        serializer.is_valid(raise_exception=True)

        validated_data = serializer.validated_data
        [data.pop("runtime_configuration") for data in validated_data]

        self.test_job = serializer.save()[0]

        print(
            f"[REPORT] Job:{self.test_job.pk}, status:'{self.test_job.status}',",
            f"Playbooks: {self.test_job.playbooks_to_execute}",
        )

        start_playbooks(self.test_job.pk, {})

        poll_result = PollingFunction(self, function_name="start_playbooks")
        return poll_result
