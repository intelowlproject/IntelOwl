from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.investigations_manager.models import Investigation
from api_app.investigations_manager.serializers import (
    InvestigationSerializer,
    InvestigationTreeSerializer,
)
from api_app.models import Job
from tests import CustomTestCase


class InvestigationSerializerTestCase(CustomTestCase):
    def test_to_representation(self):
        an1 = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        job = Job.objects.create(
            user=self.user,
            analyzable=an1,
            status="killed",
        )
        j2 = job.add_child(
            user=self.user,
            analyzable=an1,
            status="killed",
        )
        inv: Investigation = Investigation.objects.create(name="Test", owner=self.user)
        inv.jobs.add(job)
        result = InvestigationSerializer(instance=inv).data
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
        inv.delete()
        an1.delete()


class InvestigationTreeSerializerTestCase(CustomTestCase):
    def test_to_representation(self):
        an1 = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        job = Job.objects.create(
            analyzable=an1,
            user=self.user,
            status="killed",
        )
        j2 = job.add_child(
            analyzable=an1,
            user=self.user,
            status="killed",
        )
        inv: Investigation = Investigation.objects.create(name="Test", owner=self.user)
        inv.jobs.add(job)
        result = InvestigationTreeSerializer(instance=inv).data
        self.assertIn("jobs", result)
        self.assertEqual(1, len(result["jobs"]))
        self.assertEqual(result["jobs"][0]["pk"], job.pk)
        self.assertIn("children", result["jobs"][0])
        self.assertEqual(1, len(result["jobs"][0]["children"]))
        self.assertEqual(result["jobs"][0]["children"][0]["pk"], j2.pk)
        j2.delete()
        job.delete()
        inv.delete()
        an1.delete()
