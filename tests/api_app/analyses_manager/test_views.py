from api_app.analyses_manager.models import Analysis
from api_app.helpers import get_now
from api_app.models import Job
from tests import CustomViewSetTestCase, ViewSetTestCaseMixin


class AnalysisViewSetTestCase(CustomViewSetTestCase, ViewSetTestCaseMixin):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]
    URL = "/api/analysis"

    def setUp(self):
        super().setUp()
        self.analysis = Analysis.objects.create(owner=self.user, name="test")

    def tearDown(self) -> None:
        super().tearDown()
        self.analysis.delete()

    @classmethod
    @property
    def model_class(cls):
        return Analysis

    def test_list(self):
        super().test_list()
        an = Analysis.objects.create(owner=self.user, name="test")
        self.client.force_authenticate(self.user)
        response = self.client.get(self.URL)
        result = response.json()
        self.assertEqual(result["count"], Analysis.objects.count())
        self.assertEqual(len(result["results"]), Analysis.objects.count())
        an.delete()

    def test_get(self):
        plugin = self.get_object()
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 200, response.json())

        self.client.force_authenticate(None)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 401, response.json())

        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 403, response.json())

    def test_update(self):
        plugin = self.get_object()
        response = self.client.patch(f"{self.URL}/{plugin}", data={"name": "newName"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["name"], "newName")
        self.client.force_authenticate(self.superuser)
        response = self.client.patch(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 403, response.json())

    def test_delete(self):
        analysis = self.get_object()
        self.client.force_authenticate(user=self.superuser)
        response = self.client.delete(f"{self.URL}/{analysis}")
        self.assertEqual(response.status_code, 403)
        self.client.force_authenticate(user=self.user)
        response = self.client.delete(f"{self.URL}/{analysis}")
        self.assertEqual(response.status_code, 204)
        response = self.client.delete(f"{self.URL}/{analysis}")
        self.assertEqual(response.status_code, 404)

    def test_create(self):
        response = self.client.post(f"{self.URL}", data={})
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            f"{self.URL}", data={"name": "Test2", "description": "test desc"}
        )
        self.assertEqual(response.status_code, 201)
        an = Analysis.objects.get(pk=response.json()["id"])
        self.assertEqual(an.name, "Test2")
        self.assertEqual(an.description, "test desc")

    def get_object(self):
        return self.analysis.pk

    def test_add_job(self):
        analysis = self.get_object()
        response = self.client.post(f"{self.URL}/{analysis}/add_job", data={})
        self.assertEqual(response.status_code, 400)
        job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.superuser,
        )
        response = self.client.post(
            f"{self.URL}/{analysis}/add_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 403)
        job.user = self.user
        job.save()
        response = self.client.post(
            f"{self.URL}/{analysis}/add_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.post(
            f"{self.URL}/{analysis}/add_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 400)
        job.delete()

    def test_remove_job(self):
        analysis = self.get_object()
        response = self.client.post(f"{self.URL}/{analysis}/remove_job", data={})
        self.assertEqual(response.status_code, 400)
        job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.superuser,
            finished_analysis_time=get_now(),
        )
        job2 = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.superuser,
        )
        self.analysis.jobs.add(job)
        self.analysis.jobs.add(job2)
        response = self.client.post(
            f"{self.URL}/{analysis}/remove_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 403)
        job.user = self.user
        job.save()
        response = self.client.post(
            f"{self.URL}/{analysis}/remove_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.post(
            f"{self.URL}/{analysis}/remove_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 400)
        job.delete()
        job2.delete()
