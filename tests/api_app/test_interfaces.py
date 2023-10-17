from api_app.interfaces import CreateJobsFromPlaybookInterface
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers import (
    MultipleFileAnalysisSerializer,
    MultipleObservableAnalysisSerializer,
)
from tests import CustomTestCase


class CreateJobFromPlaybookInterfaceTestCase(CustomTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.c = CreateJobsFromPlaybookInterface()
        self.c.playbook_to_execute = PlaybookConfig.objects.get(
            name="FREE_TO_USE_ANALYZERS"
        )
        self.c.name = "test"

    def test__get_file_serializer(self):
        serializer = self.c._get_file_serializer([b"test"], tlp="CLEAR", user=self.user)
        self.assertIsInstance(serializer, MultipleFileAnalysisSerializer)
        serializer.is_valid(raise_exception=True)
        jobs = serializer.save(send_task=False)
        self.assertEqual(len(jobs), 1)
        job = jobs[0]
        self.assertEqual(job.analyzed_object_name, "test.0")
        self.assertEqual(job.playbook_to_execute, self.c.playbook_to_execute)
        self.assertEqual(job.tlp, "CLEAR")
        self.assertEqual(job.file.read(), b"test")

    def test__get_observable_serializer(self):
        serializer = self.c._get_observable_serializer(
            ["google.com"], tlp="CLEAR", user=self.user
        )
        self.assertIsInstance(serializer, MultipleObservableAnalysisSerializer)
        serializer.is_valid(raise_exception=True)
        jobs = serializer.save(send_task=False)
        self.assertEqual(len(jobs), 1)
        job = jobs[0]
        self.assertEqual(job.analyzed_object_name, "google.com")
        self.assertEqual(job.playbook_to_execute, self.c.playbook_to_execute)
        self.assertEqual(job.tlp, "CLEAR")
        self.assertEqual(job.observable_classification, "domain")
