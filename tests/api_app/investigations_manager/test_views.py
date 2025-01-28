from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.helpers import get_now
from api_app.investigations_manager.models import Investigation
from api_app.models import Job
from tests import CustomViewSetTestCase, ViewSetTestCaseMixin


class InvestigationViewSetTestCase(CustomViewSetTestCase, ViewSetTestCaseMixin):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]
    URL = "/api/investigation"

    def setUp(self):
        super().setUp()
        self.investigation = Investigation.objects.create(owner=self.user, name="test")

    def tearDown(self) -> None:
        super().tearDown()
        self.investigation.delete()

    @classmethod
    @property
    def model_class(cls):
        return Investigation

    def test_list(self):
        super().test_list()
        an = Investigation.objects.create(owner=self.user, name="test")
        self.client.force_authenticate(self.user)
        response = self.client.get(self.URL)
        result = response.json()
        self.assertEqual(result["count"], Investigation.objects.count())
        self.assertEqual(len(result["results"]), Investigation.objects.count())
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
        investigation = self.get_object()
        self.client.force_authenticate(user=self.superuser)
        response = self.client.delete(f"{self.URL}/{investigation}")
        self.assertEqual(response.status_code, 403)
        self.client.force_authenticate(user=self.user)
        response = self.client.delete(f"{self.URL}/{investigation}")
        self.assertEqual(response.status_code, 204)
        response = self.client.delete(f"{self.URL}/{investigation}")
        self.assertEqual(response.status_code, 404)

    def test_create(self):
        response = self.client.post(f"{self.URL}", data={})
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            f"{self.URL}", data={"name": "Test2", "description": "test desc"}
        )
        self.assertEqual(response.status_code, 201)
        an = Investigation.objects.get(pk=response.json()["id"])
        self.assertEqual(an.name, "Test2")
        self.assertEqual(an.description, "test desc")

    def get_object(self):
        return self.investigation.pk

    def test_add_job(self):
        investigation = self.get_object()
        response = self.client.post(f"{self.URL}/{investigation}/add_job", data={})
        self.assertEqual(response.status_code, 400)
        result = response.json()
        self.assertEqual(
            result["errors"]["detail"], "You should set the `job` argument in the data"
        )
        an = Analyzable.objects.create(
            name="test.com", classification=Classification.DOMAIN
        )
        job = Job.objects.create(
            analyzable=an,
            user=self.superuser,
        )
        response = self.client.post(
            f"{self.URL}/{investigation}/add_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 403)
        job.user = self.user
        job.save()
        response = self.client.post(
            f"{self.URL}/{investigation}/add_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.post(
            f"{self.URL}/{investigation}/add_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 400)
        job.delete()
        an.delete()

    def test_remove_job(self):
        investigation = self.get_object()
        response = self.client.post(f"{self.URL}/{investigation}/remove_job", data={})
        self.assertEqual(response.status_code, 400)
        result = response.json()
        self.assertEqual(
            result["errors"]["detail"], "You should set the `job` argument in the data"
        )
        an = Analyzable.objects.create(
            name="test.com", classification=Classification.DOMAIN
        )

        job = Job.objects.create(
            analyzable=an,
            user=self.superuser,
            finished_analysis_time=get_now(),
        )
        job2 = Job.objects.create(
            analyzable=an,
            user=self.user,
            finished_analysis_time=get_now(),
        )
        self.investigation.jobs.add(job)
        self.investigation.jobs.add(job2)
        response = self.client.post(
            f"{self.URL}/{investigation}/remove_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 403)
        job.user = self.user
        job.save()
        response = self.client.post(
            f"{self.URL}/{investigation}/remove_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.post(
            f"{self.URL}/{investigation}/remove_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            f"{self.URL}/{investigation}/remove_job", data={"job": job2.pk}
        )
        self.assertEqual(response.status_code, 200)

        job.delete()
        job2.delete()
        an.delete()

    def test_get_superuser(self):
        plugin = self.get_object()
        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 403, response.json())
