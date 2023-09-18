from api_app.interfaces import CreateJobsFromPlaybookInterface
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers import FileAnalysisSerializer, ObservableAnalysisSerializer
from tests import CustomTestCase


class CreateJobFromPlaybookInterfaceTestCase(CustomTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.c = CreateJobsFromPlaybookInterface()
        self.c.playbook_to_execute = PlaybookConfig.objects.first()
        self.c.name = "test"

    def test__get_file_serializer(self):
        serializer = self.c._get_file_serializer([b"test"], tlp="CLEAN", user=self.user)
        self.assertIsInstance(serializer, FileAnalysisSerializer)
        job = serializer.save(send_task=False)
        self.assertEqual(job.analyzed_object_name, "test.1")
        self.assertEqual(job.playbook_to_execute, self.c.playbook_to_execute)
        self.assertEqual(job.tlp, "CLEAN")
        self.assertEqual(job.file.read(), b"test")

    def test__get_observable_serializer(self):
        serializer = self.c._get_observable_serializer(
            ["google.com"], tlp="CLEAN", user=self.user
        )
        self.assertIsInstance(serializer, ObservableAnalysisSerializer)
        job = serializer.save(send_task=False)
        self.assertEqual(job.analyzed_object_name, "google.com")
        self.assertEqual(job.playbook_to_execute, self.c.playbook_to_execute)
        self.assertEqual(job.tlp, "CLEAN")
        self.assertEqual(job.observable_classification, "domain")
