# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from api_app.analyzables_manager.models import Analyzable
from api_app.choices import TLP, Classification
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
        an: Investigation = Investigation.objects.create(name="Test", owner=self.user)
        # Empty investigation returns TLP.CLEAR as a TLP enum instance
        self.assertIsInstance(an.tlp, TLP)
        self.assertEqual(an.tlp.value, "CLEAR")
        self.assertEqual(an.tlp, TLP.CLEAR)

        job = Job.objects.create(
            analyzable=self.an,
            user=self.user,
            tlp="CLEAR",
        )
        an.jobs.add(job)
        an.refresh_from_db()
        self.assertEqual(an.tlp.value, "CLEAR")

        # Descendant pivot job with higher TLP must be reflected in the investigation's TLP
        child_job = job.add_child(
            analyzable=self.an,
            user=self.user,
            tlp="AMBER",
        )
        an.refresh_from_db()
        self.assertEqual(an.tlp.value, "AMBER")

        # Root job with RED
        job2 = Job.objects.create(
            analyzable=self.an,
            user=self.user,
            tlp="RED",
        )
        an.jobs.add(job2)
        an.refresh_from_db()
        self.assertEqual(an.tlp.value, "RED")

        # Removing the RED root job should leave the AMBER child job as the maximum
        job2.delete()
        an.refresh_from_db()
        self.assertEqual(an.tlp.value, "AMBER")

        child_job.delete()
        an.refresh_from_db()
        self.assertEqual(an.tlp.value, "CLEAR")

        job.delete()
        an.delete()

    def test_tags(self):
        an: Investigation = Investigation.objects.create(name="Test", owner=self.user)
        self.assertEqual(an.tags, [])

        job = Job.objects.create(
            analyzable=self.an,
            user=self.user,
        )
        tag1, _ = Tag.objects.get_or_create(label="test1", defaults={"color": gen_random_colorhex()})
        job.tags.add(tag1)
        an.jobs.add(job)
        an.refresh_from_db()
        self.assertCountEqual(an.tags, [tag1.label])

        # Descendant pivot job with a new tag must be included in investigation.tags
        child_job = job.add_child(
            analyzable=self.an,
            user=self.user,
        )
        tag2, _ = Tag.objects.get_or_create(label="test2", defaults={"color": gen_random_colorhex()})
        child_job.tags.add(tag2)
        an.refresh_from_db()
        self.assertCountEqual(an.tags, [tag1.label, tag2.label])

        child_job.delete()
        an.refresh_from_db()
        self.assertCountEqual(an.tags, [tag1.label])

        job.delete()
        an.delete()

    def test_tlp_choice_ordering_and_comparisons(self):
        # Strict ordering
        self.assertTrue(TLP.CLEAR < TLP.GREEN < TLP.AMBER < TLP.RED)
        self.assertTrue(TLP.RED > TLP.AMBER > TLP.GREEN > TLP.CLEAR)

        # Less/greater or equal
        self.assertTrue(TLP.CLEAR <= TLP.CLEAR)
        self.assertTrue(TLP.CLEAR <= TLP.GREEN)
        self.assertTrue(TLP.RED >= TLP.RED)
        self.assertTrue(TLP.RED >= TLP.AMBER)

        # Comparison with string choices
        self.assertTrue(TLP.RED >= "AMBER")
        self.assertTrue(TLP.CLEAR <= "GREEN")
        self.assertTrue(TLP.AMBER > "GREEN")
        self.assertTrue(TLP.GREEN < "RED")

        # Unsupported comparison raises TypeError with informative message
        with self.assertRaises(TypeError) as ctx:
            _ = TLP.RED > 42
        self.assertIn("Cannot compare TLP with", str(ctx.exception))
