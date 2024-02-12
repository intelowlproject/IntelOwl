from api_app.interfaces import CreateJobsFromPlaybookInterface
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers.job import (
    MultipleFileJobSerializer,
    MultipleObservableJobSerializer,
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
        parent_job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
        )
        serializer = self.c._get_file_serializer([b"test"], tlp="CLEAR", user=self.user)
        self.assertIsInstance(serializer, MultipleFileJobSerializer)
        serializer.is_valid(raise_exception=True)
        jobs = serializer.save(send_task=False, parent=parent_job)
        self.assertEqual(len(jobs), 1)
        job = jobs[0]
        self.assertEqual(job.analyzed_object_name, "test.0")
        self.assertEqual(job.playbook_to_execute, self.c.playbook_to_execute)
        self.assertEqual(job.tlp, "CLEAR")
        self.assertEqual(job.file.read(), b"test")
        self.assertIsNone(job.analysis)
        self.assertIsNotNone(parent_job.analysis)
        parent_job.delete()

    def test__get_observable_serializer(self):
        parent_job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
        )
        serializer = self.c._get_observable_serializer(
            ["google.com"], tlp="CLEAR", user=self.user
        )
        self.assertIsInstance(serializer, MultipleObservableJobSerializer)
        serializer.is_valid(raise_exception=True)
        jobs = serializer.save(send_task=False, parent=parent_job)
        self.assertEqual(len(jobs), 1)
        job = jobs[0]
        self.assertEqual(job.analyzed_object_name, "google.com")
        self.assertEqual(job.playbook_to_execute, self.c.playbook_to_execute)
        self.assertEqual(job.tlp, "CLEAR")
        self.assertEqual(job.observable_classification, "domain")
        self.assertIsNone(job.analysis)
        self.assertIsNotNone(parent_job.analysis)
        parent_job.delete()

    def test__multiple_jobs_analysis(self):
        parent_job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
        )
        self.assertIsNone(parent_job.analysis)
        serializer = self.c._get_observable_serializer(
            ["google.com", "google2.com"], tlp="CLEAR", user=self.user
        )
        self.assertIsInstance(serializer, MultipleObservableJobSerializer)
        serializer.is_valid(raise_exception=True)
        jobs = serializer.save(send_task=False, parent=parent_job)
        self.assertEqual(len(jobs), 2)
        job1, job2 = jobs
        self.assertIsNone(job1.analysis)
        self.assertIsNone(job2.analysis)
        self.assertCountEqual(
            list(parent_job.get_children().values_list("pk", flat=True)),
            [job1.pk, job2.pk],
        )
        self.assertIsNotNone(parent_job.analysis)
        parent_job.delete()
