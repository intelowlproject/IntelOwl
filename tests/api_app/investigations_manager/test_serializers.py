from api_app.investigations_manager.models import Investigation
from api_app.investigations_manager.serializers import (
    InvestigationSerializer,
    InvestigationTreeSerializer,
)
from api_app.models import Job
from tests import CustomTestCase


class InvestigationSerializerTestCase(CustomTestCase):
    def test_to_representation(self):
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
        an: Investigation = Investigation.objects.create(name="Test", owner=self.user)
        an.jobs.add(job)
        result = InvestigationSerializer(instance=an).data
        self.assertIn("total_jobs", result)
        self.assertEqual(result["total_jobs"], 2)
        self.assertIn("tags", result)
        self.assertIn("tlp", result)
        self.assertIn("name", result)
        self.assertEqual(result["name"], "Test")
        self.assertIn("jobs", result)
        self.assertCountEqual(result["jobs"], [job.pk])
        j2.delete()
        job.delete()
        an.delete()


class InvestigationTreeSerializerTestCase(CustomTestCase):
    def test_to_representation(self):
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
        an: Investigation = Investigation.objects.create(name="Test", owner=self.user)
        an.jobs.add(job)
        result = InvestigationTreeSerializer(instance=an).data
        self.assertIn("jobs", result)
        self.assertEqual(1, len(result["jobs"]))
        self.assertEqual(result["jobs"][0]["pk"], job.pk)
        self.assertIn("children", result["jobs"][0])
        self.assertEqual(1, len(result["jobs"][0]["children"]))
        self.assertEqual(result["jobs"][0]["children"][0]["pk"], j2.pk)
        j2.delete()
        job.delete()
        an.delete()
