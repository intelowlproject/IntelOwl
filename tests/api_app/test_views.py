# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os

from django.contrib.auth import get_user_model
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from api_app.analyzers_manager.constants import ObservableTypes
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.core.models import Parameter
from api_app.models import Comment, Job, PluginConfig, Tag
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization

from .. import CustomAPITestCase

User = get_user_model()


class PluginConfigViewSetTestCase(CustomAPITestCase):
    URL = "/api/plugin-config"

    def setUp(self):
        super().setUp()
        PluginConfig.objects.all().delete()

    def test_plugins_config_viewset(self):
        org = Organization.create("test_org", self.user)

        response = self.client.get(self.URL, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertFalse(content)
        param = Parameter.objects.create(
            is_secret=True,
            name="api_key_name",
            analyzer_config=AnalyzerConfig.objects.get(name="AbuseIPDB"),
            required=True,
            type="str",
        )
        # if the user is owner of an org, he should get the org secret
        pc = PluginConfig(
            value="supersecret",
            for_organization=True,
            owner=self.user,
            parameter=param,
        )
        pc.clean()
        pc.save()
        self.assertEqual(pc.owner, org.owner)
        response = self.client.get(self.URL, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        first_item = content[0]
        self.assertEqual(first_item["value"], "supersecret")

        # second personal item
        secret_owner = PluginConfig(
            value="supersecret_user_only",
            for_organization=False,
            owner=self.user,
            parameter=param,
        )
        secret_owner.save()
        response = self.client.get(self.URL, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        second_item = content[1]
        self.assertEqual(second_item["value"], "supersecret_user_only")

        # if a standard user who does not belong to any org tries to get a secret,
        # they should not find anything
        self.standard_user = User.objects.create_user(
            username="standard_user",
            email="standard_user@intelowl.com",
            password="test",
        )
        self.standard_user.save()
        self.standard_user_client = APIClient()
        self.standard_user_client.force_authenticate(user=self.standard_user)
        response = self.standard_user_client.get(self.URL, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertFalse(content)

        # if a standard user tries to get the secret of his org,
        # he should have a "redacted" value
        Membership(user=self.standard_user, organization=org, is_owner=False).save()
        response = self.standard_user_client.get(self.URL, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        first_item = content[0]
        self.assertEqual(first_item["value"], "redacted")
        secret_owner.refresh_from_db()
        self.assertEqual(secret_owner.value, "supersecret_user_only")

        # third superuser secret
        secret_owner = PluginConfig(
            value="supersecret_low_privilege",
            for_organization=False,
            owner=self.standard_user,
            parameter=param,
        )
        secret_owner.save()
        response = self.standard_user_client.get(self.URL, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        second_item = content[1]
        self.assertEqual(second_item["value"], "supersecret_low_privilege")
        param2 = Parameter.objects.create(
            is_secret=True,
            name="api_key_name",
            analyzer_config=AnalyzerConfig.objects.get(name="Auth0"),
            required=True,
        )
        # if there are 2 secrets for different services, the user should get them both
        secret_owner = PluginConfig(
            value="supersecret_low_privilege_third",
            for_organization=False,
            owner=self.standard_user,
            parameter=param2,
        )
        secret_owner.save()
        response = self.standard_user_client.get(self.URL, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        third_item = content[2]
        self.assertEqual(third_item["value"], "supersecret_low_privilege_third")
        param2.delete()
        param.delete()


class CommentViewSetTestCase(CustomAPITestCase):
    comment_url = reverse("comments-list")

    def setUp(self):
        super().setUp()
        self.job = Job.objects.create(
            user=self.superuser,
            is_sample=False,
            observable_name="8.8.8.8",
            observable_classification=ObservableTypes.IP,
        )
        self.job2 = Job.objects.create(
            user=self.superuser,
            is_sample=False,
            observable_name="8.8.8.8",
            observable_classification=ObservableTypes.IP,
        )
        self.comment = Comment.objects.create(
            job=self.job, user=self.superuser, content="test"
        )
        self.comment.save()

    def tearDown(self) -> None:
        super().tearDown()
        self.job.delete()
        self.job2.delete()
        self.comment.delete()

    def test_list_200(self):
        response = self.client.get(self.comment_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json().get("count"), 1)

    def test_create_201(self):
        data = {"job_id": self.job.id, "content": "test2"}
        response = self.client.post(self.comment_url, data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json().get("content"), "test2")

    def test_delete(self):
        response = self.client.delete(f"{self.comment_url}/{self.comment.pk}")
        self.assertEqual(response.status_code, 403)
        self.client.force_authenticate(self.superuser)
        response = self.client.delete(f"{self.comment_url}/{self.comment.pk}")
        self.assertEqual(response.status_code, 204)
        self.assertEqual(0, Comment.objects.all().count())

    def test_get(self):
        response = self.client.get(f"{self.comment_url}/{self.comment.pk}")
        self.assertEqual(response.status_code, 403)
        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.comment_url}/{self.comment.pk}")
        self.assertEqual(response.status_code, 200)


class JobViewsetTests(CustomAPITestCase):
    jobs_list_uri = reverse("jobs-list")
    agg_status_uri = reverse("jobs-aggregate-status")
    agg_type_uri = reverse("jobs-aggregate-type")
    agg_observable_classification_uri = reverse(
        "jobs-aggregate-observable-classification"
    )
    agg_file_mimetype_uri = reverse("jobs-aggregate-file-mimetype")
    agg_observable_name_uri = reverse("jobs-aggregate-observable-name")
    agg_file_name_uri = reverse("jobs-aggregate-md5")

    def setUp(self):
        super().setUp()
        self.job, _ = Job.objects.get_or_create(
            **{
                "user": self.superuser,
                "is_sample": False,
                "observable_name": os.environ.get("TEST_IP"),
                "md5": os.environ.get("TEST_MD5"),
                "observable_classification": "ip",
            }
        )
        self.job2, _ = Job.objects.get_or_create(
            **{
                "user": self.superuser,
                "is_sample": True,
                "md5": "test.file",
                "file_name": "test.file",
                "file_mimetype": "application/x-dosexec",
            }
        )

    def test_list_200(self):
        response = self.client.get(self.jobs_list_uri)
        content = response.json()
        msg = (response, content)

        self.assertEqual(200, response.status_code, msg=msg)
        self.assertIn("count", content, msg=msg)
        self.assertIn("total_pages", content, msg=msg)
        self.assertIn("results", content, msg=msg)

    def test_retrieve_200(self):
        response = self.client.get(f"{self.jobs_list_uri}/{self.job.id}")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(content["id"], self.job.id, msg=msg)
        self.assertEqual(content["status"], self.job.status, msg=msg)

    def test_delete(self):
        self.assertEqual(Job.objects.count(), 2)
        response = self.client.delete(f"{self.jobs_list_uri}/{self.job.id}")
        self.assertEqual(response.status_code, 403)
        self.client.force_authenticate(user=self.job.user)
        response = self.client.delete(f"{self.jobs_list_uri}/{self.job.id}")
        self.assertEqual(response.status_code, 204)
        self.assertEqual(Job.objects.count(), 1)

    # @action endpoints

    def test_kill(self):
        job = Job.objects.create(status=Job.Status.RUNNING, user=self.superuser)
        self.assertEqual(job.status, Job.Status.RUNNING)
        uri = reverse("jobs-kill", args=[job.pk])
        response = self.client.patch(uri)

        self.assertEqual(response.status_code, 403)
        self.client.force_authenticate(user=self.job.user)
        response = self.client.patch(uri)
        self.assertEqual(response.status_code, 204)
        job.refresh_from_db()

        self.assertEqual(job.status, Job.Status.KILLED)

    def test_kill_400(self):
        # create a new job whose status is not "running"
        job = Job.objects.create(
            status=Job.Status.REPORTED_WITHOUT_FAILS, user=self.superuser
        )
        uri = reverse("jobs-kill", args=[job.pk])
        self.client.force_authenticate(user=self.job.user)
        response = self.client.patch(uri)
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertDictEqual(
            content["errors"], {"detail": "Job is not running"}, msg=msg
        )

    # aggregation endpoints

    def test_agg_status_200(self):
        resp = self.client.get(self.agg_status_uri)
        content = resp.json()
        msg = (resp, content)

        self.assertEqual(resp.status_code, 200, msg)
        for field in ["date", *Job.Status.values]:
            self.assertIn(
                field,
                content[0],
                msg=msg,
            )

    def test_agg_type_200(self):
        resp = self.client.get(self.agg_type_uri)
        content = resp.json()
        msg = (resp, content)

        self.assertEqual(resp.status_code, 200, msg)
        self.assertEqual(resp.status_code, 200, msg)
        for field in ["date", "file", "observable"]:
            self.assertIn(
                field,
                content[0],
                msg=msg,
            )

    def test_agg_observable_classification_200(self):
        resp = self.client.get(self.agg_observable_classification_uri)
        content = resp.json()
        msg = (resp, content)

        self.assertEqual(resp.status_code, 200, msg)
        for field in ["date", *ObservableTypes.values]:
            self.assertIn(
                field,
                content[0],
                msg=msg,
            )

    def test_agg_file_mimetype_200(self):
        resp = self.client.get(self.agg_file_mimetype_uri)
        content = resp.json()
        msg = (resp, content)

        self.assertEqual(resp.status_code, 200, msg)
        for field in ["date", *content["values"]]:
            self.assertIn(
                field,
                content["aggregation"][0],
                msg=msg,
            )

    def test_agg_observable_name_200(self):
        resp = self.client.get(self.agg_observable_name_uri)
        content = resp.json()
        msg = (resp, content)

        self.assertEqual(resp.status_code, 200, msg)
        for field in content["values"]:
            self.assertIn(
                field,
                content["aggregation"],
                msg=msg,
            )

    def test_agg_file_name_200(self):
        resp = self.client.get(self.agg_file_name_uri)
        content = resp.json()
        msg = (resp, content)

        self.assertEqual(resp.status_code, 200, msg)
        for field in content["values"]:
            self.assertIn(
                field,
                content["aggregation"],
                msg=msg,
            )


class TagViewsetTests(CustomAPITestCase):

    tags_list_uri = reverse("tags-list")

    def setUp(self):
        super().setUp()
        self.client.force_authenticate(user=self.superuser)
        self.tag, _ = Tag.objects.get_or_create(label="testlabel1", color="#FF5733")

    def test_create_201(self):
        self.assertEqual(Tag.objects.count(), 1)
        data = {"label": "testlabel2", "color": "#91EE28"}
        response = self.client.post(self.tags_list_uri, data)
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 201, msg=msg)
        self.assertDictContainsSubset(data, content, msg=msg)
        self.assertEqual(Tag.objects.count(), 2)

    def test_create_400(self):
        self.assertEqual(Tag.objects.count(), 1)
        data = {"label": "testlabel2", "color": "NOT_A_COLOR"}
        response = self.client.post(self.tags_list_uri, data)
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 400, msg=msg)

    def test_list_200(self):
        response = self.client.get(self.tags_list_uri)
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 200, msg=msg)

    def test_retrieve_200(self):
        response = self.client.get(f"{self.tags_list_uri}/{self.tag.id}")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 200, msg=msg)

    def test_update_200(self):
        new_data = {"label": "newTestLabel", "color": "#765A54"}
        response = self.client.put(f"{self.tags_list_uri}/{self.tag.id}", new_data)
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 200, msg=msg)
        self.assertDictContainsSubset(new_data, content, msg=msg)

    def test_delete_204(self):
        self.assertEqual(Tag.objects.count(), 1)
        response = self.client.delete(f"{self.tags_list_uri}/{self.tag.id}")

        self.assertEqual(response.status_code, 204)
        self.assertEqual(Tag.objects.count(), 0)
