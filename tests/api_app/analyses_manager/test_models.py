from api_app.analyses_manager.models import Analysis
from api_app.helpers import gen_random_colorhex
from api_app.models import Job, Tag
from tests import CustomTestCase


class AnalysisTestCase(CustomTestCase):
    def test_set_correct_status_created(self):
        an: Analysis = Analysis.objects.create(name="Test", owner=self.user)
        self.assertEqual(an.status, "created")
        an.set_correct_status()
        self.assertEqual(an.status, "created")
        an.delete()

    def test_set_correct_status_running(self):
        job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
        )
        an: Analysis = Analysis.objects.create(name="Test", owner=self.user)
        an.jobs.add(job)
        self.assertEqual(an.status, "created")
        an.set_correct_status()
        self.assertEqual(an.status, "running")
        job.delete()
        an.delete()

    def test_set_correct_status_running2(self):
        job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
        )
        job2 = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
            status="killed",
        )
        an: Analysis = Analysis.objects.create(name="Test", owner=self.user)
        an.jobs.add(job)
        an.jobs.add(job2)
        an.set_correct_status()
        self.assertEqual(an.status, "running")
        job.delete()
        job2.delete()
        an.delete()

    def test_set_correct_status_concluded(self):
        job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
            status="killed",
        )
        an: Analysis = Analysis.objects.create(name="Test", owner=self.user)
        an.jobs.add(job)
        self.assertEqual(an.status, "created")
        an.set_correct_status()
        self.assertEqual(an.status, "concluded")
        job.delete()
        an.delete()

    def test_jobs_count(self):
        job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
            status="killed",
        )
        j2 = job.add_child(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
            status="killed",
        )
        an: Analysis = Analysis.objects.create(name="Test", owner=self.user)
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
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
            tlp="CLEAR",
        )
        job2 = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
            tlp="RED",
        )
        an: Analysis = Analysis.objects.create(name="Test", owner=self.user)
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
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
        )
        job2 = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
        )

        tag1, _ = Tag.objects.get_or_create(
            label="test1", defaults={"color": gen_random_colorhex()}
        )
        tag2, _ = Tag.objects.get_or_create(
            label="test2", defaults={"color": gen_random_colorhex()}
        )
        job.tags.add(tag1)
        job2.tags.add(tag2)
        an: Analysis = Analysis.objects.create(name="Test", owner=self.user)
        an.jobs.add(job)
        an.refresh_from_db()
        self.assertCountEqual(an.tags, [tag1.label])
        an.jobs.add(job2)
        an.refresh_from_db()
        self.assertCountEqual(an.tags, [tag1.label, tag2.label])
        job.delete()
        job2.delete()
        an.delete()
