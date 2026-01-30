from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.interfaces import CreateJobsFromPlaybookInterface
from api_app.investigations_manager.models import Investigation
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
        self.c.playbooks_choice = PlaybookConfig.objects.filter(name="FREE_TO_USE_ANALYZERS")
        self.c.name = "test"

    def test__get_file_serializer(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        parent_job = Job.objects.create(
            analyzable=an,
            user=self.user,
        )
        serializer = self.c._get_file_serializer(
            [b"test"],
            tlp="CLEAR",
            user=self.user,
            playbook_to_execute=self.c.playbooks_choice.first(),
        )
        self.assertIsInstance(serializer, MultipleFileJobSerializer)
        serializer.is_valid(raise_exception=True)
        jobs = serializer.save(send_task=False, parent=parent_job)
        self.assertEqual(len(jobs), 1)
        job = jobs[0]
        self.assertEqual(job.analyzable.name, "test.0")
        self.assertEqual(job.playbook_to_execute, self.c.playbooks_choice.first())
        self.assertEqual(job.tlp, "CLEAR")
        self.assertEqual(job.analyzable.read(), b"test")
        self.assertIsNone(job.investigation)
        self.assertIsNotNone(parent_job.investigation)
        parent_job.delete()
        an.delete()

    def test__get_observable_serializer(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        parent_job = Job.objects.create(
            analyzable=an,
            user=self.user,
        )
        serializer = self.c._get_observable_serializer(
            ["google.com"],
            tlp="CLEAR",
            user=self.user,
            playbook_to_execute=self.c.playbooks_choice.first(),
        )
        self.assertIsInstance(serializer, MultipleObservableJobSerializer)
        serializer.is_valid(raise_exception=True)
        jobs = serializer.save(send_task=False, parent=parent_job)
        self.assertEqual(len(jobs), 1)
        job = jobs[0]
        self.assertEqual(job.analyzable.name, "google.com")
        self.assertEqual(job.playbook_to_execute, self.c.playbooks_choice.first())
        self.assertEqual(job.tlp, "CLEAR")
        self.assertEqual(job.analyzable.classification, "domain")
        self.assertIsNone(job.investigation)
        self.assertIsNotNone(parent_job.investigation)
        parent_job.delete()
        an.delete()

    def test__multiple_jobs_investigations(self):
        investigation_count = Investigation.objects.count()
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        parent_job = Job.objects.create(
            analyzable=an,
            user=self.user,
        )
        self.assertIsNone(parent_job.investigation)
        serializer = self.c._get_observable_serializer(
            ["google.com", "google2.com"],
            tlp="CLEAR",
            user=self.user,
            playbook_to_execute=self.c.playbooks_choice.first(),
        )
        self.assertIsInstance(serializer, MultipleObservableJobSerializer)
        serializer.is_valid(raise_exception=True)
        jobs = serializer.save(send_task=False, parent=parent_job)
        self.assertEqual(len(jobs), 2)
        job1, job2 = jobs
        self.assertIsNone(job1.investigation)
        self.assertIsNone(job2.investigation)
        self.assertCountEqual(
            list(parent_job.get_children().values_list("pk", flat=True)),
            [job1.pk, job2.pk],
        )
        self.assertIsNotNone(parent_job.investigation)
        self.assertEqual(investigation_count + 1, Investigation.objects.count())
        parent_job.delete()
        job1.delete()
        job2.delete()
        an.delete()

    def test__multiple_jobs_investigation_with_parent_in_investigation(self):
        investigation = Investigation.objects.create(owner=self.user, name="test")
        investigation_count = Investigation.objects.count()
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        parent_job = Job.objects.create(
            analyzable=an,
            user=self.user,
        )
        investigation.jobs.set([parent_job])
        # the parent has an investigation
        self.assertIsNotNone(parent_job.investigation)
        serializer = self.c._get_observable_serializer(
            ["google.com", "google2.com"],
            tlp="CLEAR",
            user=self.user,
            playbook_to_execute=self.c.playbooks_choice.first(),
        )
        self.assertIsInstance(serializer, MultipleObservableJobSerializer)
        serializer.is_valid(raise_exception=True)
        jobs = serializer.save(send_task=False, parent=parent_job)
        self.assertEqual(len(jobs), 2)
        job1, job2 = jobs
        self.assertIsNone(job1.investigation)
        self.assertIsNone(job2.investigation)
        self.assertCountEqual(
            list(parent_job.get_children().values_list("pk", flat=True)),
            [job1.pk, job2.pk],
        )
        # number of investigation should not change
        self.assertEqual(investigation_count, Investigation.objects.count())
        # same children
        self.assertCountEqual(list(investigation.jobs.values_list("pk", flat=True)), [parent_job.pk])
        self.assertCountEqual(
            list(parent_job.get_children().values_list("pk", flat=True)),
            [job1.pk, job2.pk],
        )
        parent_job.delete()
        investigation.delete()
        an.delete()
