import os

from django.test import TransactionTestCase

from api_app.serializers import PlaybookObservableAnalysisSerializer
from intel_owl.tasks import start_playbooks
from tests import PollingFunction


class PlaybooksScriptTestCase(TransactionTestCase):
    def setUp(self):
        playbook_to_test = os.environ.get("TEST_PLAYBOOK", "").split(",")
        self.playbook_to_test = playbook_to_test
        return super().setUp()

    def tearDown(self):
        self.test_job.delete()
        return super().tearDown()

    def test_start_playbooks_observable(self, *args, **kwargs):
        print(
            "\n[START] -----"
            f"{self.__class__.__name__}.test_start_playbooks_observable----"
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
