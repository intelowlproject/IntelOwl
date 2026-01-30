from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.helpers import gen_random_colorhex
from api_app.investigations_manager.models import Investigation
from api_app.models import Job, Tag
from tests import CustomTestCase


class InvestigationTestCase(CustomTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.an.delete()

    def test_set_correct_status_created(self):
        an: Investigation = Investigation.objects.create(name="Test", owner=self.user)
        self.assertEqual(an.status, "created")
        an.set_correct_status()
        self.assertEqual(an.status, "created")
        an.delete()

    def test_set_correct_status_running(self):
        job = Job.objects.create(
            analyzable=self.an,
            user=self.user,
            status=Job.STATUSES.REPORTED_WITH_FAILS,
        )
        an: Investigation = Investigation.objects.create(name="Test", owner=self.user)
        an.jobs.add(job)
        self.assertEqual(an.status, "created")
        an.set_correct_status()
        self.assertEqual(an.status, "concluded")
        job.add_child(
            analyzable=self.an,
            user=self.user,
            status=Job.STATUSES.PENDING,
        )
        an.refresh_from_db()
        an.set_correct_status()
        self.assertEqual(an.status, "running")
        job.delete()
        an.delete()

    def test_set_correct_status_running2(self):
        job = Job.objects.create(
            analyzable=self.an,
            user=self.user,
        )
        job2 = Job.objects.create(
            analyzable=self.an,
            user=self.user,
            status="killed",
        )
        an: Investigation = Investigation.objects.create(name="Test", owner=self.user)
        an.jobs.add(job)
        an.jobs.add(job2)
        an.set_correct_status()
        self.assertEqual(an.status, "running")
        job.delete()
        job2.delete()
        an.delete()

    def test_set_correct_status_concluded(self):
        job = Job.objects.create(
            analyzable=self.an,
            user=self.user,
            status="killed",
        )
        an: Investigation = Investigation.objects.create(name="Test", owner=self.user)
        an.jobs.add(job)
        self.assertEqual(an.status, "created")
        an.set_correct_status()
        self.assertEqual(an.status, "concluded")
        job.delete()
        an.delete()

    def test_jobs_count(self):
        job = Job.objects.create(
            analyzable=self.an,
            user=self.user,
            status="killed",
        )
        j2 = job.add_child(
            analyzable=self.an,
            user=self.user,
            status="killed",
        )
        an: Investigation = Investigation.objects.create(name="Test", owner=self.user)
        an.jobs.add(job)
        an.refresh_from_db()
        self.assertEqual(an.total_jobs, 2)
        j2.delete()
        self.assertEqual(an.total_jobs, 1)
        job.delete()
        self.assertEqual(an.total_jobs, 0)
        an.delete()

    def test_tlp(self):
        job = Job.objects.create(
            analyzable=self.an,
            user=self.user,
            tlp="CLEAR",
        )
        job2 = Job.objects.create(
            analyzable=self.an,
            user=self.user,
            tlp="RED",
        )
        an: Investigation = Investigation.objects.create(name="Test", owner=self.user)
        an.jobs.add(job)
        self.assertEqual(an.tlp.value, "CLEAR")
        an.jobs.add(job2)
        an.refresh_from_db()
        self.assertEqual(an.tlp.value, "RED")
        job.delete()
        an.refresh_from_db()
        self.assertEqual(an.tlp.value, "RED")
        job2.delete()
        an.delete()

    def test_tags(self):
        job = Job.objects.create(
            analyzable=self.an,
            user=self.user,
        )
        job2 = Job.objects.create(
            analyzable=self.an,
            user=self.user,
        )

        tag1, _ = Tag.objects.get_or_create(label="test1", defaults={"color": gen_random_colorhex()})
        tag2, _ = Tag.objects.get_or_create(label="test2", defaults={"color": gen_random_colorhex()})
        job.tags.add(tag1)
        job2.tags.add(tag2)
        an: Investigation = Investigation.objects.create(name="Test", owner=self.user)
        an.jobs.add(job)
        an.refresh_from_db()
        self.assertCountEqual(an.tags, [tag1.label])
        an.jobs.add(job2)
        an.refresh_from_db()
        self.assertCountEqual(an.tags, [tag1.label, tag2.label])
        job.delete()
        job2.delete()
        an.delete()
