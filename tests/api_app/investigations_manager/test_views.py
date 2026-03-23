import datetime
from unittest.mock import patch

from rest_framework.test import APITestCase

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.helpers import get_now
from api_app.investigations_manager.models import Investigation
from api_app.models import Job
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from certego_saas.apps.user.models import User


@patch(
    "api_app.investigations_manager.models.now",
    return_value=datetime.datetime(2025, 1, 2, tzinfo=datetime.timezone.utc),
)
class InvestigationViewSetTestCase(APITestCase):
    URL = "/api/investigation"

    def setUp(self):
        super().setUp()
        self.first_user, _ = User.objects.get_or_create(username="first_inv_user")
        self.second_user, _ = User.objects.get_or_create(username="second_inv_user")
        self.another_org_user, _ = User.objects.get_or_create(username="another_inv_user")
        self.org, _ = Organization.objects.get_or_create(name="inv organization")
        Membership.objects.get_or_create(user=self.first_user, organization=self.org, is_owner=True)
        Membership.objects.get_or_create(user=self.second_user, organization=self.org, is_owner=False)
        self.first_investigation = Investigation.objects.create(
            owner=self.first_user, name="first investigation"
        )
        self.second_investigation = Investigation.objects.create(
            owner=self.second_user, name="second investigation"
        )
        self.third_investigation = Investigation.objects.create(
            owner=self.second_user, name="third investigation", for_organization=True
        )
        self.another_investigation = Investigation.objects.create(
            owner=self.another_org_user, name="another investigation"
        )
        self.an, _ = Analyzable.objects.get_or_create(
            name="sub.test.com", classification=Classification.DOMAIN
        )
        self.second_inv_job, _ = Job.objects.get_or_create(
            user=self.second_user,
            analyzable=self.an,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            investigation=self.third_investigation,
            finished_analysis_time=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
        )
        self.client.force_authenticate(self.first_user)

    def tearDown(self) -> None:
        super().tearDown()
        self.second_inv_job.delete()
        self.first_investigation.delete()
        self.second_investigation.delete()
        self.third_investigation.delete()
        self.another_investigation.delete()
        self.an.delete()
        self.org.delete()
        self.first_user.delete()
        self.second_user.delete()
        self.another_org_user.delete()

    def test_list(self, *args, **kwargs):
        all_investigation_response = self.client.get(self.URL)
        self.assertEqual(all_investigation_response.status_code, 200)
        all_investigation_response_data = all_investigation_response.json()
        self.assertEqual(all_investigation_response_data["count"], 2)
        self.assertCountEqual(
            [e["name"] for e in all_investigation_response_data["results"]],
            ["first investigation", "third investigation"],
        )
        # test filter for analyzed name
        filtered_investigation_response = self.client.get(self.URL, data={"analyzed_object_name": "test.com"})
        self.assertEqual(filtered_investigation_response.status_code, 200)
        filtered_investigation_response_data = filtered_investigation_response.json()
        self.assertEqual(filtered_investigation_response_data["count"], 1)
        self.assertCountEqual(
            [e["name"] for e in filtered_investigation_response_data["results"]],
            ["third investigation"],
        )

    def test_get(self, *args, **kwargs):
        response = self.client.get(f"{self.URL}/{self.first_investigation.pk}")
        self.assertEqual(response.status_code, 200, response.json())

        self.client.force_authenticate(None)
        response = self.client.get(f"{self.URL}/{self.first_investigation.pk}")
        self.assertEqual(response.status_code, 401, response.json())

        self.client.force_authenticate(self.second_user)
        response = self.client.get(f"{self.URL}/{self.first_investigation.pk}")
        self.assertEqual(response.status_code, 403, response.json())

    def test_update(self, *args, **kwargs):
        response = self.client.patch(f"{self.URL}/{self.first_investigation.pk}", data={"name": "newName"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["name"], "newName")
        self.client.force_authenticate(self.second_user)
        response = self.client.patch(f"{self.URL}/{self.first_investigation.pk}")
        self.assertEqual(response.status_code, 403, response.json())

    def test_delete(self, *args, **kwargs):
        self.client.force_authenticate(user=self.second_user)
        response = self.client.delete(f"{self.URL}/{self.first_investigation.pk}")
        self.assertEqual(response.status_code, 403)
        self.client.force_authenticate(user=self.first_user)
        response = self.client.delete(f"{self.URL}/{self.first_investigation.pk}")
        self.assertEqual(response.status_code, 204)
        response = self.client.delete(f"{self.URL}/{self.first_investigation.pk}")
        self.assertEqual(response.status_code, 404)

    def test_create(self, *args, **kwargs):
        response = self.client.post(f"{self.URL}", data={})
        self.assertEqual(response.status_code, 400)
        response = self.client.post(f"{self.URL}", data={"name": "Test2", "description": "test desc"})
        self.assertEqual(response.status_code, 201)
        an = Investigation.objects.get(pk=response.json()["id"])
        self.assertEqual(an.name, "Test2")
        self.assertEqual(an.description, "test desc")

    def test_add_job(self, *args, **kwargs):
        response = self.client.post(f"{self.URL}/{self.first_investigation.pk}/add_job", data={})
        self.assertEqual(response.status_code, 400)
        result = response.json()
        self.assertEqual(result["errors"]["detail"], "You should set the `job` argument in the data")
        job = Job.objects.create(
            user=self.second_user,
            analyzable=self.an,
        )
        response = self.client.post(f"{self.URL}/{self.first_investigation.pk}/add_job", data={"job": job.pk})
        self.assertEqual(response.status_code, 403)
        job.user = self.first_user
        job.save()
        response = self.client.post(f"{self.URL}/{self.first_investigation.pk}/add_job", data={"job": job.pk})
        self.assertEqual(response.status_code, 200)
        response = self.client.post(f"{self.URL}/{self.first_investigation.pk}/add_job", data={"job": job.pk})
        self.assertEqual(response.status_code, 400)
        job.delete()

    def test_remove_job(self, *args, **kwargs):
        response = self.client.post(f"{self.URL}/{self.first_investigation.pk}/remove_job", data={})
        self.assertEqual(response.status_code, 400)
        result = response.json()
        self.assertEqual(result["errors"]["detail"], "You should set the `job` argument in the data")
        job = Job.objects.create(
            user=self.second_user,
            analyzable=self.an,
            finished_analysis_time=get_now(),
        )
        job2 = Job.objects.create(
            analyzable=self.an,
            user=self.first_user,
            finished_analysis_time=get_now(),
        )
        self.first_investigation.jobs.add(job)
        self.first_investigation.jobs.add(job2)
        response = self.client.post(
            f"{self.URL}/{self.first_investigation.pk}/remove_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 403)
        job.user = self.first_user
        job.save()
        response = self.client.post(
            f"{self.URL}/{self.first_investigation.pk}/remove_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.post(
            f"{self.URL}/{self.first_investigation.pk}/remove_job", data={"job": job.pk}
        )
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            f"{self.URL}/{self.first_investigation.pk}/remove_job",
            data={"job": job2.pk},
        )
        self.assertEqual(response.status_code, 200)

        job.delete()
        job2.delete()
