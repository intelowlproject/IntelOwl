from api_app.analyses_manager.models import Analysis
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

    def test_delete(self):
        analysis = self.get_object()
        self.client.force_authenticate(user=self.superuser)
        response = self.client.delete(f"{self.URL}/{analysis}")
        self.assertEqual(response.status_code, 404)
        self.client.force_authenticate(user=self.user)
        response = self.client.delete(f"{self.URL}/{analysis}")
        self.assertEqual(response.status_code, 200, response.json())
        response = self.client.delete(f"{self.URL}/{analysis}")
        self.assertEqual(response.status_code, 404)

    def test_create(self):
        ...


    def get_object(self):
        return self.analysis.pk

    def test_add_job(self):
        analysis = self.get_object()
        response = self.client.post(f"{self.URL}/{analysis}", data={})
        self.assertEqual(response.status_code, 400)
        job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.superuser,
        )
        response = self.client.post(f"{self.URL}/{analysis}", data={"job": job.pk})
        self.assertEqual(response.status_code, 403)
        job.user = self.user
        job.save()
        response = self.client.post(f"{self.URL}/{analysis}", data={"job": job.pk})
        self.assertEqual(response.status_code, 202)
        response = self.client.post(f"{self.URL}/{analysis}", data={"job": job.pk})
        self.assertEqual(response.status_code, 403)
