# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json

from django.test import TestCase

from api_app.analyzables_manager.models import Analyzable
from api_app.chatbot_manager.agent.tools import build_tools
from api_app.choices import TLP, Classification
from api_app.data_model_manager.models import DomainDataModel
from api_app.models import Job
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from certego_saas.apps.user.models import User


class DataModelToolTestCase(TestCase):
    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="dm_tool_user")
        self.other_user, _ = User.objects.get_or_create(username="dm_tool_other_user")
        self.org_member, _ = User.objects.get_or_create(username="dm_tool_org_member")
        self.org, _ = Organization.objects.get_or_create(name="dm tool org")
        Membership.objects.get_or_create(user=self.user, organization=self.org, is_owner=True)
        Membership.objects.get_or_create(user=self.org_member, organization=self.org, is_owner=False)
        self.analyzable, _ = Analyzable.objects.get_or_create(
            name="dm.example.com",
            classification=Classification.DOMAIN,
        )
        # Job with an aggregated data model attached (as the analysis pipeline would set it).
        self.job_with_dm = Job.objects.create(
            user=self.user,
            analyzable=self.analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
        )
        self.data_model = DomainDataModel.objects.create()
        self.job_with_dm.data_model = self.data_model
        self.job_with_dm.save()
        # Job without a data model.
        self.job_without_dm = Job.objects.create(
            user=self.user,
            analyzable=self.analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
        )
        # Another user's job, RED so it stays inaccessible under visible_for_user.
        self.other_job = Job.objects.create(
            user=self.other_user,
            analyzable=self.analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            tlp=TLP.RED.value,
        )
        # Org-mate's RED job: reachable via organization membership (no data model attached;
        # the point is that it resolves instead of returning "not accessible").
        self.org_job = Job.objects.create(
            user=self.org_member,
            analyzable=self.analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            tlp=TLP.RED.value,
        )
        self.get_data_model = {t.name: t for t in build_tools(user=self.user)}["get_data_model"]

    def tearDown(self):
        Job.objects.filter(user__in=[self.user, self.other_user, self.org_member]).delete()
        Membership.objects.filter(organization=self.org).delete()
        self.org.delete()
        self.data_model.delete()

    def test_get_data_model_returns_serialized(self):
        data = json.loads(self.get_data_model.invoke({"job_id": self.job_with_dm.pk}))
        self.assertEqual(data["errors"], [])
        self.assertTrue(data["data_model"])
        self.assertIn("reliability", data["data_model"])

    def test_get_data_model_empty_when_absent(self):
        data = json.loads(self.get_data_model.invoke({"job_id": self.job_without_dm.pk}))
        self.assertEqual(data["errors"], [])
        self.assertEqual(data["data_model"], {})

    def test_get_data_model_forbidden_other_user(self):
        data = json.loads(self.get_data_model.invoke({"job_id": self.other_job.pk}))
        self.assertEqual(data["data_model"], {})
        self.assertTrue(data["errors"])
        self.assertIn("not found or not accessible", data["errors"][0])

    def test_get_data_model_org_shared_visible(self):
        # An org-mate's RED job is reachable via organization membership (UI parity);
        # the data model is empty because none is attached, but it is NOT "not accessible".
        data = json.loads(self.get_data_model.invoke({"job_id": self.org_job.pk}))
        self.assertEqual(data["errors"], [])
        self.assertEqual(data["data_model"], {})
