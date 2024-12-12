# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import datetime
from unittest.mock import MagicMock, patch
from zoneinfo import ZoneInfo

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.utils.timezone import now
from elasticsearch_dsl.query import Bool, Exists, Range, Term
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from api_app.analyzers_manager.constants import ObservableTypes
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import ReportStatus
from api_app.models import Comment, Job, Parameter, PluginConfig, Tag
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization

from .. import CustomViewSetTestCase, ViewSetTestCaseMixin

User = get_user_model()


class PluginConfigViewSetTestCase(CustomViewSetTestCase):
    URL = "/api/plugin-config"
    custom_config_uri = reverse("plugin-config-list")

    def setUp(self):
        super().setUp()
        PluginConfig.objects.all().delete()

    def test_get(self):
        org = Organization.create("test_org", self.user)
        Membership.objects.create(
            user=self.admin, organization=org, is_owner=False, is_admin=True
        )
        ac = AnalyzerConfig.objects.get(name="AbuseIPDB")
        # logged out
        self.client.logout()
        response = self.client.get(self.URL, {}, format="json")
        self.assertEqual(response.status_code, 401, response.json())

        param = Parameter.objects.create(
            is_secret=True,
            name="mynewparameter",
            python_module=ac.python_module,
            required=True,
            type="str",
        )
        pc = PluginConfig(
            value="supersecret",
            for_organization=True,
            owner=self.user,
            parameter=param,
            analyzer_config=ac,
        )
        pc.full_clean()
        pc.save()
        self.assertEqual(pc.owner, org.owner)

        # if the user is owner of an org, he should get the org secret
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.URL, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        first_item = content[0]
        self.assertEqual(first_item["value"], "supersecret")

        # if the user is admin of an org, he should get the org secret
        self.client.force_authenticate(user=self.admin)
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
            analyzer_config=ac,
        )
        secret_owner.save()

        # user can see own personal secret
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.URL, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        second_item = content[1]
        self.assertEqual(second_item["value"], "supersecret_user_only")

        # other users cannot see user's personal items
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(self.URL, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertEqual(1, len(content))

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
        Membership(
            user=self.standard_user, organization=org, is_owner=False, is_admin=False
        ).save()
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
            analyzer_config=ac,
        )
        secret_owner.save()
        response = self.standard_user_client.get(self.URL, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        second_item = content[1]
        self.assertEqual(second_item["value"], "supersecret_low_privilege")
        ac = AnalyzerConfig.objects.get(name="Auth0")
        # if there are 2 secrets for different services, the user should get them both
        param2 = Parameter.objects.create(
            is_secret=True,
            name="mysecondsupernewsecret",
            python_module=ac.python_module,
            required=True,
        )
        secret_owner = PluginConfig(
            value="supersecret_low_privilege_third",
            for_organization=False,
            owner=self.standard_user,
            parameter=param2,
            analyzer_config=ac,
        )
        secret_owner.save()
        response = self.standard_user_client.get(self.URL, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        third_item = content[2]
        self.assertEqual(third_item["value"], "supersecret_low_privilege_third")
        param2.delete()
        param.delete()
        PluginConfig.objects.filter(value__startswith="supersecret").delete()
        org.delete()

    def test_list(self):
        ac = AnalyzerConfig.objects.first()
        param = Parameter.objects.create(
            python_module=ac.python_module,
            name="test",
            is_secret=True,
            required=True,
            type="str",
        )
        org0 = Organization.objects.create(name="testorg0")
        org1 = Organization.objects.create(name="testorg1")
        another_owner = User.objects.create_user(
            username="another_owner",
            email="another_owner@intelowl.com",
            password="test",
        )
        another_owner.save()
        m0 = Membership.objects.create(
            organization=org0, user=self.superuser, is_owner=True
        )
        m1 = Membership.objects.create(
            organization=org0, user=self.admin, is_owner=False, is_admin=True
        )
        m2 = Membership.objects.create(
            organization=org1, user=self.user, is_owner=False, is_admin=False
        )
        m3 = Membership.objects.create(
            organization=org1, user=another_owner, is_owner=True
        )
        pc0 = PluginConfig.objects.create(
            parameter=param,
            analyzer_config=ac,
            value="value",
            owner=self.superuser,
            for_organization=True,
        )
        pc1 = PluginConfig.objects.create(
            parameter=param,
            analyzer_config=ac,
            value="value",
            owner=another_owner,
            for_organization=True,
        )
        # logged out
        self.client.logout()
        response = self.client.get(f"{self.custom_config_uri}")
        self.assertEqual(response.status_code, 401)

        # the owner can see the config of own org
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(f"{self.custom_config_uri}")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        # the owner cannot see configs of other orgs (pc1)
        self.assertEqual(1, len(result))
        needle = None
        for obj in result:
            if obj["id"] == pc0.pk:
                needle = obj
        self.assertIsNotNone(needle)
        self.assertIn("type", needle)
        self.assertEqual(needle["type"], "1")
        self.assertIn("config_type", needle)
        self.assertEqual(needle["config_type"], "2")
        self.assertIn("plugin_name", needle)
        self.assertEqual(needle["plugin_name"], ac.name)
        self.assertIn("organization", needle)
        self.assertEqual(needle["organization"], "testorg0")
        self.assertIn("value", needle)
        self.assertEqual(needle["value"], "value")
        self.assertIn("attribute", needle)
        self.assertEqual(needle["attribute"], "test")

        # an admin can see the config of own org
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(f"{self.custom_config_uri}")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        # an admin cannot see configs of other orgs (pc1)
        self.assertEqual(1, len(result))
        needle = None
        for obj in result:
            if obj["id"] == pc0.pk:
                needle = obj
        self.assertIsNotNone(needle)
        self.assertIn("type", needle)
        self.assertEqual(needle["type"], "1")
        self.assertIn("config_type", needle)
        self.assertEqual(needle["config_type"], "2")
        self.assertIn("plugin_name", needle)
        self.assertEqual(needle["plugin_name"], ac.name)
        self.assertIn("organization", needle)
        self.assertEqual(needle["organization"], "testorg0")
        self.assertIn("value", needle)
        self.assertEqual(needle["value"], "value")
        self.assertIn("attribute", needle)
        self.assertEqual(needle["attribute"], "test")

        # a user in the org can see the config with redacted data
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{self.custom_config_uri}")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        # a user cannot see configs of other orgs (pc0)
        self.assertEqual(1, len(result))
        needle = None
        for obj in result:
            if obj["id"] == pc1.pk:
                needle = obj
        self.assertIsNotNone(needle)
        self.assertIn("type", needle)
        self.assertEqual(needle["type"], "1")
        self.assertIn("config_type", needle)
        self.assertEqual(needle["config_type"], "2")
        self.assertIn("plugin_name", needle)
        self.assertEqual(needle["plugin_name"], ac.name)
        self.assertIn("organization", needle)
        self.assertEqual(needle["organization"], "testorg1")
        self.assertIn("value", needle)
        self.assertEqual(needle["value"], "redacted")
        self.assertIn("attribute", needle)
        self.assertEqual(needle["attribute"], "test")

        # a user outside the org can not see the config
        self.client.force_authenticate(user=self.guest)
        response = self.client.get(f"{self.custom_config_uri}")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(0, len(result))
        m0.delete()
        m1.delete()
        m2.delete()
        m3.delete()
        another_owner.delete()
        org0.delete()
        org1.delete()
        param.delete()


class CommentViewSetTestCase(CustomViewSetTestCase):
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


@patch(
    "api_app.views.parse_humanized_range",
    MagicMock(
        return_value=(
            datetime.datetime(2024, 11, 27, 12, tzinfo=datetime.timezone.utc),
            "day",
        )
    ),
)
class JobViewSetTests(CustomViewSetTestCase):
    jobs_list_uri = reverse("jobs-list")
    jobs_recent_scans_uri = reverse("jobs-recent-scans")
    jobs_recent_scans_user_uri = reverse("jobs-recent-scans-user")
    agg_status_uri = reverse("jobs-aggregate-status")
    agg_type_uri = reverse("jobs-aggregate-type")
    agg_observable_classification_uri = reverse(
        "jobs-aggregate-observable-classification"
    )
    agg_file_mimetype_uri = reverse("jobs-aggregate-file-mimetype")
    agg_top_playbook = reverse("jobs-aggregate-top-playbook")
    agg_top_user = reverse("jobs-aggregate-top-user")
    agg_top_tlp = reverse("jobs-aggregate-top-tlp")

    def setUp(self):
        super().setUp()
        with patch(
            "django.utils.timezone.now",
            return_value=datetime.datetime(2024, 11, 28, tzinfo=datetime.timezone.utc),
        ):
            self.job, _ = Job.objects.get_or_create(
                **{
                    "user": self.superuser,
                    "is_sample": False,
                    "observable_name": "1.2.3.4",
                    "observable_classification": "ip",
                    "playbook_to_execute": PlaybookConfig.objects.get(name="Dns"),
                    "tlp": Job.TLP.CLEAR.value,
                }
            )
            self.job2, _ = Job.objects.get_or_create(
                **{
                    "user": self.superuser,
                    "is_sample": True,
                    "md5": "test.file",
                    "file_name": "test.file",
                    "file_mimetype": "application/vnd.microsoft.portable-executable",
                    "playbook_to_execute": PlaybookConfig.objects.get(name="Dns"),
                    "tlp": Job.TLP.GREEN.value,
                }
            )

    def test_recent_scan(self):
        j1 = Job.objects.create(
            **{
                "user": self.user,
                "is_sample": False,
                "observable_name": "gigatest.com",
                "observable_classification": "domain",
                "finished_analysis_time": now() - datetime.timedelta(days=2),
            }
        )
        j2 = Job.objects.create(
            **{
                "user": self.user,
                "is_sample": False,
                "observable_name": "gigatest.com",
                "observable_classification": "domain",
                "finished_analysis_time": now() - datetime.timedelta(hours=2),
            }
        )
        response = self.client.post(self.jobs_recent_scans_uri, data={"md5": j1.md5})
        content = response.json()
        msg = (response, content)
        self.assertEqual(200, response.status_code, msg=msg)
        self.assertIsInstance(content, list)
        pks = [elem["pk"] for elem in content]
        self.assertIn(j2.pk, pks)
        self.assertIn(j1.pk, pks)

        j1.delete()
        j2.delete()

    def test_recent_scan_user(self):
        j1 = Job.objects.create(
            **{
                "user": self.user,
                "is_sample": False,
                "observable_name": "gigatest.com",
                "observable_classification": "domain",
                "finished_analysis_time": datetime.datetime(
                    2024, 11, 28, tzinfo=datetime.timezone.utc
                ),
            }
        )
        j2 = Job.objects.create(
            **{
                "user": self.superuser,
                "is_sample": False,
                "observable_name": "gigatest.com",
                "observable_classification": "domain",
                "finished_analysis_time": datetime.datetime(
                    2024, 11, 28, tzinfo=datetime.timezone.utc
                ),
            }
        )
        response = self.client.post(
            self.jobs_recent_scans_user_uri, data={"is_sample": False}
        )
        content = response.json()
        msg = (response, content)
        self.assertEqual(200, response.status_code, msg=msg)
        self.assertIsInstance(content, list)
        pks = [elem["pk"] for elem in content]
        self.assertIn(j1.pk, pks)
        self.assertNotIn(j2.pk, pks)

        j1.delete()
        j2.delete()

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
        job = Job.objects.create(
            status=Job.STATUSES.RUNNING,
            user=self.superuser,
            observable_classification="ip",
        )
        self.assertEqual(job.status, Job.STATUSES.RUNNING)
        uri = reverse("jobs-kill", args=[job.pk])
        response = self.client.patch(uri)

        self.assertEqual(response.status_code, 403)
        self.client.force_authenticate(user=self.job.user)
        response = self.client.patch(uri)
        self.assertEqual(response.status_code, 204)
        job.refresh_from_db()

        self.assertEqual(job.status, Job.STATUSES.KILLED)

    def test_kill_400(self):
        # create a new job whose status is not "running"
        job = Job.objects.create(
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            user=self.superuser,
            observable_classification="ip",
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
        self.assertEqual(
            content,
            [
                {
                    "date": "2024-11-28T00:00:00Z",
                    "pending": 2,
                    "failed": 0,
                    "reported_with_fails": 0,
                    "reported_without_fails": 0,
                }
            ],
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

    def test_agg_top_playbook_200(self):
        resp = self.client.get(self.agg_top_playbook)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.json(),
            {
                "values": ["Dns"],
                "aggregation": [{"date": "2024-11-28T00:00:00Z", "Dns": 2}],
            },
        )

    def test_agg_top_user_200(self):
        resp = self.client.get(self.agg_top_user)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.json(),
            {
                "values": ["superuser@intelowl.org"],
                "aggregation": [
                    {"date": "2024-11-28T00:00:00Z", "superuser@intelowl.org": 2}
                ],
            },
        )

    def test_agg_top_tlp_200(self):
        resp = self.client.get(self.agg_top_tlp)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.json(),
            {
                "values": ["CLEAR", "GREEN"],
                "aggregation": [
                    {"date": "2024-11-28T00:00:00Z", "CLEAR": 1, "GREEN": 1}
                ],
            },
        )


class TagViewsetTests(CustomViewSetTestCase):
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


class AbstractConfigViewSetTestCaseMixin(ViewSetTestCaseMixin, metaclass=abc.ABCMeta):
    def test_organization_disable(self):
        plugin_name = self.model_class.objects.order_by("?").first().name
        org, _ = Organization.objects.get_or_create(name="test")

        # a guest user cannot disable plugin config at org level
        response = self.client.post(f"{self.URL}/{plugin_name}/organization")
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )

        # a member cannot disable plugin config at org level
        m, _ = Membership.objects.get_or_create(
            user=self.user, organization=org, is_owner=False
        )
        response = self.client.post(f"{self.URL}/{plugin_name}/organization")
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )

        # an admin can disable plugin config at org level
        m.is_admin = True
        m.save()
        plugin = self.model_class.objects.get(name=plugin_name)
        self.assertFalse(
            plugin.disabled_in_organizations.all().exists()
        )  # isn't it disabled?
        response = self.client.post(
            f"{self.URL}/{plugin_name}/organization"
        )  # disabling it
        self.assertEqual(response.status_code, 201)
        self.assertTrue(
            plugin.disabled_in_organizations.all().exists()
        )  # now it's disabled
        response = self.client.post(
            f"{self.URL}/{plugin_name}/organization"
        )  # try to disable it again
        self.assertEqual(response.status_code, 400, response.json())
        self.assertEqual(
            1, plugin.disabled_in_organizations.all().count()
        )  # still 1 disabled
        result = response.json()
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(
            result["errors"]["detail"], f"Plugin {plugin.name} already disabled"
        )

        # an owner can disable plugin config at org level
        m.is_admin = True  # and owner is also and admin
        m.is_owner = True
        m.save()
        plugin.disabled_in_organizations.update(
            disabled=False
        )  # reset the disabled plugins
        self.assertFalse(
            plugin.disabled_in_organizations.all().exists()
        )  # isn't it disabled?
        response = self.client.post(
            f"{self.URL}/{plugin_name}/organization"
        )  # disabling it
        self.assertEqual(response.status_code, 201)
        self.assertTrue(
            plugin.disabled_in_organizations.all().exists()
        )  # now it's disabled

        plugin.disabled_in_organizations.delete()
        m.delete()
        org.delete()

    def test_organization_enable(self):
        plugin_name = self.model_class.objects.order_by("?").first().name
        org, _ = Organization.objects.get_or_create(name="test")

        # a guest user cannot enable plugin config at org level
        response = self.client.delete(f"{self.URL}/{plugin_name}/organization")
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )

        # a member cannot enable plugin config at org level
        m, _ = Membership.objects.get_or_create(
            user=self.user, organization=org, is_owner=False
        )
        response = self.client.delete(f"{self.URL}/{plugin_name}/organization")
        result = response.json()
        self.assertEqual(response.status_code, 403, result)
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )

        # an admin can enable plugin config at org level
        m, _ = Membership.objects.get_or_create(
            user=self.superuser, organization=org, is_owner=False
        )
        m.is_admin = True
        m.save()
        self.client.force_authenticate(m.user)
        plugin = self.model_class.objects.get(name=plugin_name)
        self.assertFalse(
            plugin.disabled_in_organizations.all().exists()
        )  # isn't it disabled?
        response = self.client.delete(
            f"{self.URL}/{plugin_name}/organization"
        )  # enabling it
        result = response.json()
        self.assertEqual(response.status_code, 400, result)  # validation error
        self.assertFalse(
            plugin.disabled_in_organizations.all().exists()
        )  # isn't it disabled?
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        # I can enable it but is already enabled
        self.assertEqual(
            result["errors"]["detail"], f"Plugin {plugin.name} already enabled"
        )
        plugin.orgs_configuration.update(disabled=True)  # disabling it
        response = self.client.delete(
            f"{self.URL}/{plugin_name}/organization"
        )  # disable it
        self.assertEqual(response.status_code, 202)
        self.assertFalse(
            plugin.disabled_in_organizations.all().exists()
        )  # is it enabled?

        # an owner can disable plugin config at org level
        m.is_owner = True
        m.is_admin = True  # an owner is also an admin
        m.save()
        plugin.disabled_in_organizations.update(disabled=False)
        self.assertFalse(
            plugin.disabled_in_organizations.all().exists()
        )  # isn't it disabled?
        response = self.client.delete(
            f"{self.URL}/{plugin_name}/organization"
        )  # enabling it
        result = response.json()
        self.assertEqual(response.status_code, 400, result)  # validation error
        self.assertFalse(
            plugin.disabled_in_organizations.all().exists()
        )  # isn't it disabled?
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        # I can enable it but is already enabled
        self.assertEqual(
            result["errors"]["detail"], f"Plugin {plugin.name} already enabled"
        )
        plugin.orgs_configuration.update(disabled=True)  # disabling it
        response = self.client.delete(
            f"{self.URL}/{plugin_name}/organization"
        )  # enabling it
        self.assertEqual(response.status_code, 202)
        self.assertFalse(
            plugin.disabled_in_organizations.all().exists()
        )  # is it enabled?

        m.delete()
        org.delete()


class ElasticTestCase(CustomViewSetTestCase):
    uri = reverse("plugin_report_queries")

    class ElasticObject:

        def __init__(self, response):
            self.response = response

        def to_dict(self):
            return self.response

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.org_user, _ = User.objects.get_or_create(
            is_superuser=False, username="elastic_test_user"
        )
        cls.org = Organization.objects.create(name="test_elastic_org")
        cls.membership = Membership.objects.create(
            user=cls.org_user, organization=cls.org, is_owner=True
        )

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.membership.delete()
        cls.org.delete()
        cls.org_user.delete()

    def test_not_authenticated(self):
        self.client.logout()
        response = self.client.get(self.uri)
        self.assertEqual(response.status_code, 401)

    def test_validatior_errors(self):
        # invalid plugin type
        response_invalid_plugin_type = self.client.get(
            self.uri, data={"plugin_name": "not valid"}
        )
        self.assertEqual(response_invalid_plugin_type.status_code, 400)
        self.assertEqual(
            response_invalid_plugin_type.json(),
            {"errors": {"plugin_name": ['"not valid" is not a valid choice.']}},
        )
        # invalid status
        response_invalid_status = self.client.get(
            self.uri, data={"status": "not valid"}
        )
        self.assertEqual(response_invalid_status.status_code, 400)
        self.assertEqual(
            response_invalid_status.json(),
            {"errors": {"status": ['"not valid" is not a valid choice.']}},
        )
        # start time
        response_invalid_start_time = self.client.get(
            self.uri,
            data={
                "start_start_time": datetime.datetime(2024, 12, 10, 11, 58, 46, 900001),
                "end_start_time": datetime.datetime(2024, 12, 10, 11, 58, 46, 900000),
            },
        )
        self.assertEqual(response_invalid_start_time.status_code, 400)
        self.assertEqual(
            response_invalid_start_time.json(),
            {
                "errors": {
                    "non_field_errors": [
                        "start date must be equal or lower than end date"
                    ]
                }
            },
        )
        # end time
        response_invalid_end_time = self.client.get(
            self.uri,
            data={
                "start_end_time": datetime.datetime(2024, 12, 10, 11, 58, 46, 900001),
                "end_end_time": datetime.datetime(2024, 12, 10, 11, 58, 46, 900000),
            },
        )
        self.assertEqual(response_invalid_end_time.status_code, 400)
        self.assertEqual(
            response_invalid_end_time.json(),
            {
                "errors": {
                    "non_field_errors": [
                        "start date must be equal or lower than end date"
                    ]
                }
            },
        )

    @override_settings(ELASTICSEARCH_DSL_ENABLED=True)
    @patch(
        "api_app.views.Search.execute",
        MagicMock(
            return_value=(
                [
                    ElasticObject(
                        {
                            "user": {"username": "elastic_test_user"},
                            "membership": {
                                "is_owner": True,
                                "is_admin": False,
                                "organization": {"name": "test_elastic_org"},
                            },
                            "job": {"id": 1},
                            "config": {
                                "name": "Quad9_DNS",
                                "plugin_name": "analyzer",
                            },
                            "status": "SUCCESS",
                            "start_time": "2024-11-27T09:56:59.555203Z",
                            "end_time": "2024-11-27T09:57:03.805453Z",
                            "errors": [],
                            "report": {
                                "observable": "google.com",
                                "resolutions": [
                                    {
                                        "TTL": 268,
                                        "data": "216.58.205.46",
                                        "name": "google.com.",
                                        "type": 1,
                                        "Expires": "Wed, 27 Nov 2024 10:01:31 UTC",
                                    },
                                ],
                            },
                        }
                    ),
                    ElasticObject(
                        {
                            "user": {"username": "another_user"},
                            "membership": {
                                "is_owner": False,
                                "is_admin": False,
                                "organization": {"name": "test_elastic_org"},
                            },
                            "job": {"id": 2},
                            "config": {
                                "name": "Classic_DNS",
                                "plugin_name": "analyzer",
                            },
                            "status": "SUCCESS",
                            "start_time": "2024-11-26T09:56:59.555203Z",
                            "end_time": "2024-11-26T09:57:03.805453Z",
                            "errors": [],
                            "report": {
                                "observable": "google.com",
                                "resolutions": [
                                    {
                                        "TTL": 268,
                                        "data": "216.58.205.46",
                                        "name": "google.com.",
                                        "type": 1,
                                        "Expires": "Wed, 26 Nov 2024 10:01:31 UTC",
                                    },
                                ],
                            },
                        }
                    ),
                ]
            )
        ),
    )
    def test_client_request(self):
        self.client.force_authenticate(self.org_user)
        response = self.client.get(
            self.uri,
            data={
                "report": "216.58.205.46",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "data": [
                    {
                        "job": {"id": 1},
                        "config": {
                            "name": "Quad9_DNS",
                            "plugin_name": "analyzer",
                        },
                        "status": "SUCCESS",
                        "start_time": "2024-11-27T09:56:59.555203Z",
                        "end_time": "2024-11-27T09:57:03.805453Z",
                        "errors": [],
                        "report": {
                            "observable": "google.com",
                            "resolutions": [
                                {
                                    "TTL": 268,
                                    "data": "216.58.205.46",
                                    "name": "google.com.",
                                    "type": 1,
                                    "Expires": "Wed, 27 Nov 2024 10:01:31 UTC",
                                },
                            ],
                        },
                    },
                    {
                        "job": {"id": 2},
                        "config": {
                            "name": "Classic_DNS",
                            "plugin_name": "analyzer",
                        },
                        "status": "SUCCESS",
                        "start_time": "2024-11-26T09:56:59.555203Z",
                        "end_time": "2024-11-26T09:57:03.805453Z",
                        "errors": [],
                        "report": {
                            "observable": "google.com",
                            "resolutions": [
                                {
                                    "TTL": 268,
                                    "data": "216.58.205.46",
                                    "name": "google.com.",
                                    "type": 1,
                                    "Expires": "Wed, 26 Nov 2024 10:01:31 UTC",
                                },
                            ],
                        },
                    },
                ]
            },
        )

    @override_settings(ELASTICSEARCH_DSL_ENABLED=True)
    @patch("api_app.views.Search")
    def test_elastic_request(self, mocked_search):
        self.client.force_authenticate(self.org_user)
        response = self.client.get(
            self.uri,
            data={
                "plugin_name": "analyzer",
                "name": "classic_dns",
                "status": "SUCCESS",
                "errors": False,
                "start_start_time": datetime.datetime(2024, 11, 27),
                "end_start_time": datetime.datetime(2024, 11, 28),
                "start_end_time": datetime.datetime(2024, 11, 27),
                "end_end_time": datetime.datetime(2024, 11, 28),
                "report": "8.8.8.8",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            mocked_search.return_value.query.call_args_list[0][0][0],
            Bool(
                filter=[
                    Bool(
                        should=[
                            Term(user__username="elastic_test_user"),
                            Term(membership__organization__name="elastic_test_user"),
                        ]
                    ),
                    Term(config__plugin_name="analyzer"),
                    Term(config__name="classic_dns"),
                    Term(status=ReportStatus.SUCCESS),
                    Bool(must_not=[Exists(field="errors")]),
                    Range(
                        start_time={
                            "gte": datetime.datetime(
                                2024, 11, 27, 0, 0, tzinfo=ZoneInfo(key="UTC")
                            )
                        }
                    ),
                    Range(
                        start_time={
                            "lte": datetime.datetime(
                                2024, 11, 28, 0, 0, tzinfo=ZoneInfo(key="UTC")
                            )
                        }
                    ),
                    Range(
                        end_time={
                            "gte": datetime.datetime(
                                2024, 11, 27, 0, 0, tzinfo=ZoneInfo(key="UTC")
                            )
                        }
                    ),
                    Range(
                        end_time={
                            "lte": datetime.datetime(
                                2024, 11, 28, 0, 0, tzinfo=ZoneInfo(key="UTC")
                            )
                        }
                    ),
                    Term(report="8.8.8.8"),
                ]
            ),
        )
