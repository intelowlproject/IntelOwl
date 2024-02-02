from api_app.analyses_manager.models import Analysis
from api_app.models import Job
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
