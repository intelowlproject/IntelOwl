# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import datetime
from unittest.mock import MagicMock, patch
from zoneinfo import ZoneInfo

from django.contrib.auth import get_user_model
from django.core.files import File
from django.test import override_settings
from django.utils.timezone import now
from elasticsearch_dsl.query import Bool, Exists, Range, Term
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import Classification, ReportStatus
from api_app.investigations_manager.models import Investigation
from api_app.models import Comment, Job, Parameter, PluginConfig, Tag
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization

from .. import CustomViewSetTestCase, ViewSetTestCaseMixin

User = get_user_model()


class CommentViewSetTestCase(CustomViewSetTestCase):
    comment_url = reverse("comments-list")

    def setUp(self):
        super().setUp()
        self.an1 = Analyzable.objects.create(
            name="8.8.8.8",
            classification=Classification.IP,
        )

        self.job = Job.objects.create(user=self.superuser, analyzable=self.an1)
        self.job2 = Job.objects.create(user=self.user, analyzable=self.an1)
        self.comment = Comment.objects.create(analyzable=self.an1, user=self.user, content="test")

    def tearDown(self) -> None:
        super().tearDown()
        self.comment.delete()
        self.job.delete()
        self.job2.delete()
        self.an1.delete()

    def test_list_200(self):
        self.client.force_authenticate(self.user)
        response = self.client.get(self.comment_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json().get("count"), 1)

    def test_create_201(self):
        self.client.force_authenticate(self.user)
        data = {"job_id": self.job2.id, "content": "test2"}
        response = self.client.post(self.comment_url, data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json().get("content"), "test2")

    def test_delete(self):
        self.client.force_authenticate(self.superuser)
        response = self.client.delete(f"{self.comment_url}/{self.comment.pk}")
        self.assertEqual(response.status_code, 404)
        self.client.force_authenticate(self.user)
        response = self.client.delete(f"{self.comment_url}/{self.comment.pk}")
        self.assertEqual(response.status_code, 204)
        self.assertEqual(0, Comment.objects.all().count())

    def test_get(self):
        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.comment_url}/{self.comment.pk}")
        self.assertEqual(response.status_code, 404)
        self.client.force_authenticate(self.user)
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
    agg_observable_classification_uri = reverse("jobs-aggregate-observable-classification")
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
            self.analyzable = Analyzable.objects.create(name="1.2.3.4", classification=Classification.IP)
            with open("test_files/file.exe", "rb") as f:
                self.analyzable2 = Analyzable.objects.create(
                    name="test.file",
                    classification=Classification.FILE,
                    mimetype="application/vnd.microsoft.portable-executable",
                    file=File(f),
                )
            self.analyzable3 = Analyzable.objects.create(
                name="test.com", classification=Classification.DOMAIN
            )
            with open("test_files/cve.xls", "rb") as f:
                self.analyzable4 = Analyzable.objects.create(
                    name="cve.xls",
                    classification=Classification.FILE,
                    mimetype="application/vnd.ms-excel",
                    file=File(f),
                )
            self.job = Job.objects.create(
                **{
                    "user": self.superuser,
                    "analyzable": self.analyzable,
                    "playbook_to_execute": PlaybookConfig.objects.get(name="Dns"),
                    "tlp": Job.TLP.CLEAR.value,
                }
            )
            self.job2 = Job.objects.create(
                **{
                    "user": self.superuser,
                    "analyzable": self.analyzable2,
                    "playbook_to_execute": PlaybookConfig.objects.get(name="FREE_TO_USE_ANALYZERS"),
                    "tlp": Job.TLP.GREEN.value,
                }
            )
            self.job3 = Job.objects.create(
                **{
                    "user": self.superuser,
                    "analyzable": self.analyzable3,
                    "playbook_to_execute": PlaybookConfig.objects.get(name="Dns"),
                    "tlp": Job.TLP.GREEN.value,
                }
            )
            self.job4 = Job.objects.create(
                **{
                    "user": self.superuser,
                    "analyzable": self.analyzable4,
                    "playbook_to_execute": PlaybookConfig.objects.get(name="FREE_TO_USE_ANALYZERS"),
                    "tlp": Job.TLP.GREEN.value,
                }
            )
            self.investigation1, _ = Investigation.objects.get_or_create(
                name="test_investigation1", owner=self.superuser
            )
            self.investigation1.jobs.add(self.job)
            # in this way we can check we filter investagion looking for child job and not only the one in the root
            self.job2.add_child(
                user=self.superuser,
                analyzable=self.analyzable,
                playbook_to_execute=PlaybookConfig.objects.get(name="Dns"),
                tlp=Job.TLP.AMBER.value,
            )

    def tearDown(self):
        self.job4.delete()
        self.job3.delete()
        self.job2.delete()
        self.job.delete()
        self.analyzable.delete()
        self.analyzable2.delete()

    def test_recent_scan(self):
        j1 = Job.objects.create(
            **{
                "user": self.user,
                "analyzable": self.analyzable,
                "finished_analysis_time": now() - datetime.timedelta(days=2),
            }
        )
        j2 = Job.objects.create(
            **{
                "user": self.user,
                "analyzable": self.analyzable,
                "finished_analysis_time": now() - datetime.timedelta(hours=2),
            }
        )
        response = self.client.post(self.jobs_recent_scans_uri, data={"md5": j1.analyzable.md5})
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
                "analyzable": self.analyzable,
                "finished_analysis_time": datetime.datetime(2024, 11, 28, tzinfo=datetime.timezone.utc),
            }
        )
        j2 = Job.objects.create(
            **{
                "user": self.superuser,
                "analyzable": self.analyzable,
                "finished_analysis_time": datetime.datetime(2024, 11, 28, tzinfo=datetime.timezone.utc),
            }
        )
        response = self.client.post(self.jobs_recent_scans_user_uri, data={"is_sample": False})
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

    def test_list_filter_observable(self):
        response = self.client.get(self.jobs_list_uri, {"is_sample": False})
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertEqual(response_data["count"], 2)
        print(response_data)
        self.assertCountEqual(
            list({job["file_name"] for job in response_data["results"]}),
            ["1.2.3.4", "test.com"],
        )

    def test_list_filter_sample(self):
        response = self.client.get(self.jobs_list_uri, {"is_sample": True})
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertEqual(response_data["count"], 2)
        self.assertCountEqual(
            list({job["observable_name"] for job in response_data["results"]}),
            ["cve.xls", "test.file"],
        )

    def test_list_filter_test_observable_type(self):
        response = self.client.get(self.jobs_list_uri, {"type": "domain"})
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertCountEqual(
            list({job["observable_name"] for job in response_data["results"]}),
            ["test.com"],
        )

    def test_list_filter_test_mimetype(self):
        response = self.client.get(
            self.jobs_list_uri,
            {"type": "application/vnd.microsoft.portable-executable"},
        )
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertCountEqual(
            list({job["observable_name"] for job in response_data["results"]}),
            ["test.file"],
        )

    def test_retrieve_200(self):
        response = self.client.get(f"{self.jobs_list_uri}/{self.job.id}")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(content["id"], self.job.id, msg=msg)
        self.assertEqual(content["status"], self.job.status, msg=msg)
        self.assertEqual(content["investigation_id"], self.investigation1.pk)
        self.assertEqual(content["investigation_name"], self.investigation1.name)
        self.assertEqual(content["analyzable_id"], self.analyzable.pk)

    def test_delete(self):
        self.assertEqual(Job.objects.count(), 5)
        response = self.client.delete(f"{self.jobs_list_uri}/{self.job.id}")
        self.assertEqual(response.status_code, 403)
        self.client.force_authenticate(user=self.job.user)
        response = self.client.delete(f"{self.jobs_list_uri}/{self.job.id}")
        self.assertEqual(response.status_code, 204)
        self.assertEqual(Job.objects.count(), 4)

    # @action endpoints

    def test_kill(self):
        job = Job.objects.create(
            status=Job.STATUSES.RUNNING,
            user=self.superuser,
            analyzable=self.analyzable,
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
            analyzable=self.analyzable,
        )
        uri = reverse("jobs-kill", args=[job.pk])
        self.client.force_authenticate(user=self.job.user)
        response = self.client.patch(uri)
        content = response.json()
        msg = (response, content)
        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertDictEqual(content["errors"], {"detail": "Job is not running"}, msg=msg)

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
                    "pending": 5,
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
        for field in ["date", *Classification.values[:-1]]:
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
                "values": ["Dns", "FREE_TO_USE_ANALYZERS"],
                "aggregation": [
                    {
                        "date": "2024-11-28T00:00:00Z",
                        "Dns": 3,
                        "FREE_TO_USE_ANALYZERS": 2,
                    }
                ],
            },
        )

    def test_agg_top_user_200(self):
        u = User.objects.create(
            username="test ;space@intelowl.org",
            email="test ;space@intelowl.org",
            is_superuser=False,
        )
        with patch(
            "django.utils.timezone.now",
            return_value=datetime.datetime(2024, 11, 28, tzinfo=datetime.timezone.utc),
        ):
            job, _ = Job.objects.get_or_create(
                **{
                    "user": u,
                    "analyzable": self.analyzable,
                    "playbook_to_execute": PlaybookConfig.objects.get(name="Dns"),
                    "tlp": Job.TLP.CLEAR.value,
                }
            )
        resp = self.client.get(self.agg_top_user)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.json(),
            {
                "values": ["superuser@intelowl.org", "test ;space@intelowl.org"],
                "aggregation": [
                    {
                        "date": "2024-11-28T00:00:00Z",
                        "superuser@intelowl.org": 5,
                        "testspace@intelowl.org": 1,
                    },
                ],
            },
        )
        job.delete()
        u.delete()

    def test_agg_top_tlp_200(self):
        resp = self.client.get(self.agg_top_tlp)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.json(),
            {
                "values": ["AMBER", "CLEAR", "GREEN"],
                "aggregation": [{"date": "2024-11-28T00:00:00Z", "CLEAR": 1, "GREEN": 3, "AMBER": 1}],
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
        self.assertEqual(result["detail"], "You do not have permission to perform this action.")

        # a member cannot disable plugin config at org level
        m, _ = Membership.objects.get_or_create(user=self.user, organization=org, is_owner=False)
        response = self.client.post(f"{self.URL}/{plugin_name}/organization")
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(result["detail"], "You do not have permission to perform this action.")

        # an admin can disable plugin config at org level
        m.is_admin = True
        m.save()
        plugin = self.model_class.objects.get(name=plugin_name)
        self.assertFalse(plugin.disabled_in_organizations.all().exists())  # isn't it disabled?
        response = self.client.post(f"{self.URL}/{plugin_name}/organization")  # disabling it
        self.assertEqual(response.status_code, 201)
        self.assertTrue(plugin.disabled_in_organizations.all().exists())  # now it's disabled
        response = self.client.post(f"{self.URL}/{plugin_name}/organization")  # try to disable it again
        self.assertEqual(response.status_code, 400, response.json())
        self.assertEqual(1, plugin.disabled_in_organizations.all().count())  # still 1 disabled
        result = response.json()
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(result["errors"]["detail"], f"Plugin {plugin.name} already disabled")

        # an owner can disable plugin config at org level
        m.is_admin = True  # and owner is also and admin
        m.is_owner = True
        m.save()
        plugin.disabled_in_organizations.update(disabled=False)  # reset the disabled plugins
        self.assertFalse(plugin.disabled_in_organizations.all().exists())  # isn't it disabled?
        response = self.client.post(f"{self.URL}/{plugin_name}/organization")  # disabling it
        self.assertEqual(response.status_code, 201)
        self.assertTrue(plugin.disabled_in_organizations.all().exists())  # now it's disabled

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
        self.assertEqual(result["detail"], "You do not have permission to perform this action.")

        # a member cannot enable plugin config at org level
        m, _ = Membership.objects.get_or_create(user=self.user, organization=org, is_owner=False)
        response = self.client.delete(f"{self.URL}/{plugin_name}/organization")
        result = response.json()
        self.assertEqual(response.status_code, 403, result)
        self.assertIn("detail", result)
        self.assertEqual(result["detail"], "You do not have permission to perform this action.")

        # an admin can enable plugin config at org level
        m, _ = Membership.objects.get_or_create(user=self.superuser, organization=org, is_owner=False)
        m.is_admin = True
        m.save()
        self.client.force_authenticate(m.user)
        plugin = self.model_class.objects.get(name=plugin_name)
        self.assertFalse(plugin.disabled_in_organizations.all().exists())  # isn't it disabled?
        response = self.client.delete(f"{self.URL}/{plugin_name}/organization")  # enabling it
        result = response.json()
        self.assertEqual(response.status_code, 400, result)  # validation error
        self.assertFalse(plugin.disabled_in_organizations.all().exists())  # isn't it disabled?
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        # I can enable it but is already enabled
        self.assertEqual(result["errors"]["detail"], f"Plugin {plugin.name} already enabled")
        plugin.orgs_configuration.update(disabled=True)  # disabling it
        response = self.client.delete(f"{self.URL}/{plugin_name}/organization")  # disable it
        self.assertEqual(response.status_code, 202)
        self.assertFalse(plugin.disabled_in_organizations.all().exists())  # is it enabled?

        # an owner can disable plugin config at org level
        m.is_owner = True
        m.is_admin = True  # an owner is also an admin
        m.save()
        plugin.disabled_in_organizations.update(disabled=False)
        self.assertFalse(plugin.disabled_in_organizations.all().exists())  # isn't it disabled?
        response = self.client.delete(f"{self.URL}/{plugin_name}/organization")  # enabling it
        result = response.json()
        self.assertEqual(response.status_code, 400, result)  # validation error
        self.assertFalse(plugin.disabled_in_organizations.all().exists())  # isn't it disabled?
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        # I can enable it but is already enabled
        self.assertEqual(result["errors"]["detail"], f"Plugin {plugin.name} already enabled")
        plugin.orgs_configuration.update(disabled=True)  # disabling it
        response = self.client.delete(f"{self.URL}/{plugin_name}/organization")  # enabling it
        self.assertEqual(response.status_code, 202)
        self.assertFalse(plugin.disabled_in_organizations.all().exists())  # is it enabled?

        m.delete()
        org.delete()


class PluginConfigViewSetTestCase(CustomViewSetTestCase):
    def setUp(self):
        super().setUp()

    def test_plugin_config(self):
        org = Organization.create("test_org", self.user)
        Membership.objects.create(user=self.admin, organization=org, is_owner=False, is_admin=True)
        ac = AnalyzerConfig.objects.get(name="AbuseIPDB")
        uri = f"/api/analyzer/{ac.name}/plugin_config"

        # logged out
        self.client.logout()
        response = self.client.get(uri, {}, format="json")
        self.assertEqual(response.status_code, 401)

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
        response = self.client.get(uri, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        org_config = content["organization_config"]
        user_config = content["user_config"]

        for config in [*org_config, *user_config]:
            if config["attribute"] == "mynewparameter":
                self.assertEqual(config["value"], "supersecret")

        # if the user is admin of an org, he should get the org secret
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(uri, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        org_config = content["organization_config"]
        user_config = content["user_config"]

        for config in [*org_config, *user_config]:
            if config["attribute"] == "mynewparameter":
                self.assertEqual(config["value"], "supersecret")

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
        response = self.client.get(uri, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        org_config = content["organization_config"]
        user_config = content["user_config"]

        for config in org_config:
            if config["attribute"] == "mynewparameter":
                self.assertEqual(config["value"], "supersecret")
        for config in user_config:
            if config["attribute"] == "mynewparameter":
                self.assertEqual(config["value"], "supersecret_user_only")

        # other users cannot see user's personal items
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(uri, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        org_config = content["organization_config"]
        user_config = content["user_config"]

        for config in org_config:
            if config["attribute"] == "mynewparameter":
                self.assertEqual(config["value"], "supersecret")
        for config in user_config:
            if config["attribute"] == "mynewparameter":
                self.assertNotEqual(config["value"], "supersecret_user_only")
                self.assertEqual(config["value"], "supersecret")

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
        response = self.standard_user_client.get(uri, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        org_config = content["organization_config"]
        user_config = content["user_config"]
        self.assertEqual(org_config, [])

        for config in user_config:
            if config["attribute"] == "mynewparameter":
                self.assertEqual(config["value"], None)

        # if a standard user tries to get the secret of his org,
        # he should have a "redacted" value
        Membership(user=self.standard_user, organization=org, is_owner=False, is_admin=False).save()
        response = self.standard_user_client.get(uri, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        org_config = content["organization_config"]
        user_config = content["user_config"]

        for config in [*org_config, *user_config]:
            if config["attribute"] == "mynewparameter":
                self.assertEqual(config["value"], "redacted")

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
        response = self.standard_user_client.get(uri, {}, format="json")
        self.assertEqual(response.status_code, 200)
        content = response.json()
        org_config = content["organization_config"]
        user_config = content["user_config"]

        for config in org_config:
            if config["attribute"] == "mynewparameter":
                self.assertEqual(config["value"], "redacted")
        for config in user_config:
            if config["attribute"] == "mynewparameter":
                self.assertEqual(config["value"], "supersecret_low_privilege")

        param.delete()
        PluginConfig.objects.filter(value__startswith="supersecret").delete()
        org.delete()

    def test_plugin_config_list(self):
        ac = AnalyzerConfig.objects.first()
        uri = f"/api/analyzer/{ac.name}/plugin_config"
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
        m0 = Membership.objects.create(organization=org0, user=self.superuser, is_owner=True)
        m1 = Membership.objects.create(organization=org0, user=self.admin, is_owner=False, is_admin=True)
        m2 = Membership.objects.create(organization=org1, user=self.user, is_owner=False, is_admin=False)
        m3 = Membership.objects.create(organization=org1, user=another_owner, is_owner=True)
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
        response = self.client.get(uri)
        self.assertEqual(response.status_code, 401)

        # the owner can see the config of own org
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(uri)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        org_config = result["organization_config"]
        needle = None
        for obj in org_config:
            if obj["attribute"] == pc0.attribute:
                needle = obj
            # the owner cannot see configs of other orgs (pc1)
            if "organization" in obj.keys() and obj["organization"] is not None:
                self.assertEqual(obj["organization"], "testorg0")
        self.assertIsNotNone(needle)
        self.assertIn("type", needle)
        self.assertEqual(needle["type"], param.type)
        self.assertIn("organization", needle)
        self.assertEqual(needle["organization"], "testorg0")
        self.assertIn("value", needle)
        self.assertEqual(needle["value"], "value")
        self.assertIn("attribute", needle)
        self.assertEqual(needle["attribute"], "test")
        self.assertIn("required", needle)
        self.assertEqual(needle["required"], param.required)
        self.assertIn("is_secret", needle)
        self.assertEqual(needle["is_secret"], param.is_secret)

        # an admin can see the config of own org
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(uri)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        org_config = result["organization_config"]
        needle = None
        for obj in org_config:
            if obj["attribute"] == pc0.attribute:
                needle = obj
            # an admin cannot see configs of other orgs (pc1)
            if "organization" in obj.keys() and obj["organization"] is not None:
                self.assertEqual(obj["organization"], "testorg0")
        self.assertIsNotNone(needle)
        self.assertIn("type", needle)
        self.assertEqual(needle["type"], param.type)
        self.assertIn("organization", needle)
        self.assertEqual(needle["organization"], "testorg0")
        self.assertIn("value", needle)
        self.assertEqual(needle["value"], "value")
        self.assertIn("attribute", needle)
        self.assertEqual(needle["attribute"], "test")
        self.assertIn("required", needle)
        self.assertEqual(needle["required"], param.required)
        self.assertIn("is_secret", needle)
        self.assertEqual(needle["is_secret"], param.is_secret)

        # a user in the org can see the config with redacted data
        self.client.force_authenticate(user=self.user)
        response = self.client.get(uri)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        org_config = result["organization_config"]
        needle = None
        for obj in org_config:
            if obj["attribute"] == pc1.attribute:
                needle = obj
            # a user cannot see configs of other orgs (pc0)
            if "organization" in obj.keys() and obj["organization"] is not None:
                self.assertEqual(obj["organization"], "testorg1")
        self.assertIsNotNone(needle)
        self.assertIn("type", needle)
        self.assertEqual(needle["type"], param.type)
        self.assertIn("organization", needle)
        self.assertEqual(needle["organization"], "testorg1")
        self.assertIn("value", needle)
        self.assertEqual(needle["value"], "redacted")
        self.assertIn("attribute", needle)
        self.assertEqual(needle["attribute"], "test")
        self.assertIn("required", needle)
        self.assertEqual(needle["required"], param.required)
        self.assertIn("is_secret", needle)
        self.assertEqual(needle["is_secret"], param.is_secret)

        # a user outside the org can not see the config
        self.client.force_authenticate(user=self.guest)
        response = self.client.get(uri)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        org_config = result["organization_config"]
        self.assertEqual(org_config, [])
        m0.delete()
        m1.delete()
        m2.delete()
        m3.delete()
        another_owner.delete()
        org0.delete()
        org1.delete()
        param.delete()

    def test_update(self):
        org = Organization.create("test_org", self.superuser)
        Membership.objects.create(user=self.admin, organization=org, is_owner=False, is_admin=True)
        Membership.objects.create(user=self.user, organization=org, is_owner=False, is_admin=False)
        ac = AnalyzerConfig.objects.get(name="AbuseIPDB")
        uri = f"/api/analyzer/{ac.name}/plugin_config"

        # logged out
        self.client.logout()
        response = self.client.patch(uri, {}, format="json")
        self.assertEqual(response.status_code, 401)

        param = Parameter.objects.create(
            is_secret=True,
            name="mynewparameter",
            python_module=ac.python_module,
            required=True,
            type="str",
        )
        param2 = Parameter.objects.create(
            is_secret=True,
            name="mynewparameter2",
            python_module=ac.python_module,
            required=True,
            type="str",
        )
        pc = PluginConfig(
            value="supersecret",
            for_organization=True,
            owner=self.superuser,
            parameter=param,
            analyzer_config=ac,
        )
        pc2 = PluginConfig(
            value="supersecret2",
            for_organization=True,
            owner=self.superuser,
            parameter=param2,
            analyzer_config=ac,
        )
        pc.full_clean()
        pc.save()
        self.assertEqual(pc.owner, org.owner)
        pc2.full_clean()
        pc2.save()
        self.assertEqual(pc2.owner, org.owner)

        # owner can update org secret
        self.client.force_authenticate(user=self.superuser)
        payload = [
            {
                "id": pc.pk,
                "attribute": "mynewparameter",
                "value": "new_org_supersecret",
            },
            {
                "id": pc2.pk,
                "attribute": "mynewparameter2",
                "value": "new_org_supersecret2",
            },
        ]
        response = self.client.patch(uri, payload, format="json")
        self.assertEqual(response.status_code, 200)
        pc1 = PluginConfig.objects.get(id=pc.pk)
        self.assertEqual(pc1.value, "new_org_supersecret")

        # admin can update org secret
        self.client.force_authenticate(user=self.admin)
        payload = [
            {
                "id": pc.pk,
                "attribute": "mynewparameter",
                "value": "new_org_supersecret_admin",
            }
        ]
        response = self.client.patch(uri, payload, format="json")
        self.assertEqual(response.status_code, 200)
        pc1 = PluginConfig.objects.get(id=pc.pk)
        self.assertEqual(pc1.value, "new_org_supersecret_admin")

        # user can not update org secret
        self.client.force_authenticate(user=self.user)
        payload = [
            {
                "id": pc.pk,
                "attribute": "mynewparameter",
                "value": "new_org_supersecret_user",
            }
        ]
        response = self.client.patch(uri, payload, format="json")
        self.assertEqual(response.status_code, 403)

        # second personal item
        secret_owner = PluginConfig(
            value="supersecret_user_only",
            for_organization=False,
            owner=self.user,
            parameter=param,
            analyzer_config=ac,
        )
        secret_owner.save()

        # user can update own personal secret
        self.client.force_authenticate(user=self.user)
        payload = [
            {
                "id": secret_owner.pk,
                "attribute": "mynewparameter",
                "value": "new_supersecret_user_only",
            }
        ]

        response = self.client.patch(uri, payload, format="json")
        self.assertEqual(response.status_code, 200)
        pc_user = PluginConfig.objects.get(id=secret_owner.pk)
        self.assertEqual(pc_user.value, "new_supersecret_user_only")

        # other users cannot update user's personal items
        self.client.force_authenticate(user=self.guest)
        payload = [
            {
                "id": secret_owner.pk,
                "attribute": "mynewparameter",
                "value": "new_supersecret",
            }
        ]
        response = self.client.patch(uri, payload, format="json")
        self.assertEqual(response.status_code, 403)
        pc_user = PluginConfig.objects.get(id=secret_owner.pk)
        self.assertEqual(pc_user.value, "new_supersecret_user_only")
        self.assertNotEqual(pc_user.value, "new_supersecret")

        secret_owner.delete()
        pc.delete()

        param.delete()
        PluginConfig.objects.filter(value__startswith="supersecret").delete()
        org.delete()

    def test_create(self):
        org = Organization.create("test_org", self.superuser)
        Membership.objects.create(user=self.admin, organization=org, is_owner=False, is_admin=True)
        Membership.objects.create(user=self.user, organization=org, is_owner=False, is_admin=False)
        ac = AnalyzerConfig.objects.get(name="AbuseIPDB")
        uri = f"/api/analyzer/{ac.name}/plugin_config"

        # logged out
        self.client.logout()
        response = self.client.patch(uri, {}, format="json")
        self.assertEqual(response.status_code, 401)

        param = Parameter.objects.create(
            is_secret=True,
            name="mynewparameter",
            python_module=ac.python_module,
            required=True,
            type="str",
        )
        param2 = Parameter.objects.create(
            is_secret=True,
            name="mynewparameter2",
            python_module=ac.python_module,
            required=True,
            type="str",
        )

        # owner can create org secret
        self.client.force_authenticate(user=self.superuser)
        payload = [
            {
                "attribute": "mynewparameter",
                "value": "new_org_supersecret",
                "organization": "test_org",
                "parameter": param.pk,
                "analyzer_config": "AbuseIPDB",
            },
            {
                "attribute": "mynewparameter2",
                "value": "new_org_supersecret2",
                "organization": "test_org",
                "parameter": param2.pk,
                "analyzer_config": "AbuseIPDB",
            },
        ]
        response = self.client.post(uri, payload, format="json")
        self.assertEqual(response.status_code, 201)
        content = response.json()
        self.assertEqual(content[0]["value"], "new_org_supersecret")
        self.assertEqual(content[0]["owner"], self.superuser.username)
        pc = PluginConfig.objects.get(id=content[0]["id"])
        pc2 = PluginConfig.objects.get(id=content[1]["id"])
        self.assertTrue(pc.for_organization)
        self.assertTrue(pc2.for_organization)
        pc.delete()
        pc2.delete()

        # admin can create org secret
        self.client.force_authenticate(user=self.admin)
        payload = [
            {
                "attribute": "mynewparameter",
                "value": "new_org_supersecret_admin",
                "organization": "test_org",
                "parameter": param.pk,
                "analyzer_config": "AbuseIPDB",
            }
        ]
        response = self.client.post(uri, payload, format="json")
        self.assertEqual(response.status_code, 201)
        content = response.json()
        self.assertEqual(content[0]["value"], "new_org_supersecret_admin")
        self.assertEqual(content[0]["owner"], self.admin.username)
        pc = PluginConfig.objects.get(id=content[0]["id"])
        self.assertTrue(pc.for_organization)

        # admin can create own personal secret for same param
        payload = [
            {
                "attribute": "mynewparameter",
                "value": "new_supersecret_admin",
                "parameter": param.pk,
                "analyzer_config": "AbuseIPDB",
                "for_organization": False,
            }
        ]
        response = self.client.post(uri, payload, format="json")
        self.assertEqual(response.status_code, 201)
        content = response.json()
        self.assertEqual(content[0]["value"], "new_supersecret_admin")
        self.assertEqual(content[0]["owner"], self.admin.username)
        pc1 = PluginConfig.objects.get(id=content[0]["id"])
        self.assertFalse(pc1.for_organization)
        pc.delete()
        pc1.delete()

        # user can not create org secret
        self.client.force_authenticate(user=self.user)
        payload = [
            {
                "attribute": "mynewparameter",
                "value": "new_org_supersecret_user",
                "organization": "test_org",
                "parameter": param.pk,
                "analyzer_config": "AbuseIPDB",
            }
        ]
        response = self.client.post(uri, payload, format="json")
        self.assertEqual(response.status_code, 400)

        # user can create own personal secret
        self.client.force_authenticate(user=self.user)
        payload = [
            {
                "attribute": "mynewparameter",
                "value": "new_supersecret_user_only",
                "parameter": param.pk,
                "analyzer_config": "AbuseIPDB",
                "for_organization": False,
            }
        ]
        response = self.client.post(uri, payload, format="json")
        self.assertEqual(response.status_code, 201)
        content = response.json()
        self.assertEqual(content[0]["value"], "new_supersecret_user_only")
        self.assertEqual(content[0]["owner"], self.user.username)
        pc = PluginConfig.objects.get(id=content[0]["id"])
        self.assertFalse(pc.for_organization)

        # user can not create a second config for the same parameter
        self.client.force_authenticate(user=self.user)
        payload = [
            {
                "attribute": "mynewparameter",
                "value": "new_supersecret_user_only_copy",
                "parameter": param.pk,
                "analyzer_config": "AbuseIPDB",
                "for_organization": False,
            }
        ]
        response = self.client.post(uri, payload, format="json")
        self.assertEqual(response.status_code, 400)
        pc.delete()

        pc = PluginConfig(
            value="default_secret",
            for_organization=False,
            owner=None,
            parameter=param,
            analyzer_config=ac,
        )
        pc.full_clean()
        pc.save()
        self.assertEqual(pc.owner, None)
        self.assertFalse(pc.for_organization)

        # user create own personal secret (override dafult config)
        self.client.force_authenticate(user=self.user)
        payload = [
            {
                "attribute": "mynewparameter",
                "value": "new_user_secret",
                "parameter": param.pk,
                "analyzer_config": "AbuseIPDB",
                "for_organization": False,
            }
        ]

        response = self.client.post(uri, payload, format="json")
        self.assertEqual(response.status_code, 201)
        content = response.json()
        self.assertEqual(content[0]["value"], "new_user_secret")
        self.assertEqual(content[0]["owner"], self.user.username)
        pc1 = PluginConfig.objects.get(id=content[0]["id"])
        self.assertFalse(pc1.for_organization)
        self.assertNotEqual(pc1.id, pc.id)

        pc.delete()
        param.delete()
        PluginConfig.objects.filter(value__startswith="supersecret").delete()
        org.delete()

    def test_delete(self):
        org = Organization.create("test_org", self.superuser)
        Membership.objects.create(user=self.admin, organization=org, is_owner=False, is_admin=True)
        Membership.objects.create(user=self.user, organization=org, is_owner=False, is_admin=False)
        ac = AnalyzerConfig.objects.get(name="AbuseIPDB")
        uri = "/api/plugin-config"

        # logged out
        self.client.logout()
        response = self.client.delete(f"{uri}/1", {}, format="json")
        self.assertEqual(response.status_code, 401)

        param = Parameter.objects.create(
            is_secret=True,
            name="mynewparameter",
            python_module=ac.python_module,
            required=True,
            type="str",
        )
        pc, _ = PluginConfig.objects.get_or_create(
            value="supersecret",
            for_organization=True,
            owner=self.superuser,
            parameter=param,
            analyzer_config=ac,
        )
        self.assertEqual(pc.owner, org.owner)

        # user can not delete org secret
        self.client.force_authenticate(user=self.user)
        response = self.client.delete(f"{uri}/{pc.id}", {}, format="json")
        self.assertEqual(response.status_code, 403)

        # owner can delete org secret
        self.client.force_authenticate(user=self.superuser)
        response = self.client.delete(f"{uri}/{pc.id}", format="json")
        self.assertEqual(response.status_code, 204)

        pc, _ = PluginConfig.objects.get_or_create(
            value="supersecret",
            for_organization=True,
            owner=self.superuser,
            parameter=param,
            analyzer_config=ac,
        )
        self.assertEqual(pc.owner, org.owner)

        # admin can delete org secret
        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(f"{uri}/{pc.id}", {}, format="json")
        self.assertEqual(response.status_code, 204)

        pc, _ = PluginConfig.objects.get_or_create(
            value="supersecret",
            for_organization=False,
            owner=self.user,
            parameter=param,
            analyzer_config=ac,
        )
        self.assertEqual(pc.owner, self.user)

        # user can delete own personal secret
        self.client.force_authenticate(user=self.user)
        response = self.client.delete(f"{uri}/{pc.id}", {}, format="json")
        self.assertEqual(response.status_code, 204)

    def test_get_403(self):
        different_user = User.objects.create_user(
            username="standard2_user",
            email="standard_user@intelowl.com",
            password="test",
        )
        ac = AnalyzerConfig.objects.get(name="AbuseIPDB")
        param = Parameter.objects.create(
            is_secret=True,
            name="mynewparameter",
            python_module=ac.python_module,
            required=True,
            type="str",
        )
        pc = PluginConfig.objects.create(
            value="https://intelowl.com",
            owner=different_user,
            parameter=param,
            analyzer_config=ac,
            for_organization=False,
        )
        self.client.force_authenticate(different_user)
        response = self.client.get(reverse("plugin-config-detail", kwargs={"pk": pc.pk}))
        self.assertEqual(200, response.status_code)
        self.client.force_authenticate(self.user)
        response = self.client.get(reverse("plugin-config-detail", kwargs={"pk": pc.pk}))
        self.assertEqual(403, response.status_code)
        pc.delete()
        different_user.delete()


@override_settings(ELASTICSEARCH_DSL_ENABLED=True)
@override_settings(ELASTICSEARCH_DSL_CLIENT=None)
class ElasticTestCase(CustomViewSetTestCase):
    uri = reverse("plugin-report-queries")

    class ElasticObject:
        def __init__(self, response):
            self.response = response

        def to_dict(self):
            return self.response

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.org_user, _ = User.objects.get_or_create(is_superuser=False, username="elastic_test_user")
        cls.org = Organization.objects.create(name="test_elastic_org")
        cls.membership = Membership.objects.create(user=cls.org_user, organization=cls.org, is_owner=True)

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
        response_invalid_plugin_type = self.client.get(self.uri, data={"plugin_name": "not valid"})
        self.assertEqual(response_invalid_plugin_type.status_code, 400)
        self.assertEqual(
            response_invalid_plugin_type.json(),
            {"errors": {"plugin_name": ['"not valid" is not a valid choice.']}},
        )
        # invalid status
        response_invalid_status = self.client.get(self.uri, data={"status": "not valid"})
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
            {"errors": {"non_field_errors": ["start date must be equal or lower than end date"]}},
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
            {"errors": {"non_field_errors": ["start date must be equal or lower than end date"]}},
        )

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
                "count": 2,
                "total_pages": 1,
                "results": [
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
                ],
            },
        )

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
                            Term(membership__organization__name="test_elastic_org"),
                        ]
                    ),
                    Term(config__plugin_name="analyzer"),
                    Term(config__name="classic_dns"),
                    Term(status=ReportStatus.SUCCESS),
                    Bool(must_not=[Exists(field="errors")]),
                    Range(
                        start_time={"gte": datetime.datetime(2024, 11, 27, 0, 0, tzinfo=ZoneInfo(key="UTC"))}
                    ),
                    Range(
                        start_time={"lte": datetime.datetime(2024, 11, 28, 0, 0, tzinfo=ZoneInfo(key="UTC"))}
                    ),
                    Range(
                        end_time={"gte": datetime.datetime(2024, 11, 27, 0, 0, tzinfo=ZoneInfo(key="UTC"))}
                    ),
                    Range(
                        end_time={"lte": datetime.datetime(2024, 11, 28, 0, 0, tzinfo=ZoneInfo(key="UTC"))}
                    ),
                    Term(report="8.8.8.8"),
                ]
            ),
        )
