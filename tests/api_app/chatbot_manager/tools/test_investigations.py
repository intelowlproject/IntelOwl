# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json

from django.test import TestCase

from api_app.analyzables_manager.models import Analyzable
from api_app.chatbot_manager.agent.tools import build_tools
from api_app.choices import Classification
from api_app.investigations_manager.models import Investigation
from api_app.models import Job
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from certego_saas.apps.user.models import User


class InvestigationToolsTestCase(TestCase):
    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="inv_tool_user")
        # Same organization as self.user: used to test that org-shared investigations are
        # visible (visible_for_user) while another member's private ones are not.
        self.org_member, _ = User.objects.get_or_create(username="inv_tool_org_member")
        self.org, _ = Organization.objects.get_or_create(name="inv tool organization")
        Membership.objects.get_or_create(user=self.user, organization=self.org, is_owner=True)
        Membership.objects.get_or_create(user=self.org_member, organization=self.org, is_owner=False)

        self.analyzable, _ = Analyzable.objects.get_or_create(
            name="inv.example.com",
            classification=Classification.DOMAIN,
        )

        self.inv_created = Investigation.objects.create(
            owner=self.user,
            name="alpha investigation",
            status=Investigation.STATUSES.CREATED.value,
        )
        self.inv_running = Investigation.objects.create(
            owner=self.user,
            name="beta investigation",
            status=Investigation.STATUSES.RUNNING.value,
        )
        # Owned by another member of the same org and shared at org level -> visible.
        self.inv_org_shared = Investigation.objects.create(
            owner=self.org_member,
            name="gamma investigation",
            status=Investigation.STATUSES.CONCLUDED.value,
            for_organization=True,
        )
        # Owned by another member but NOT shared -> must stay invisible to self.user.
        self.inv_private = Investigation.objects.create(
            owner=self.org_member,
            name="delta investigation",
            status=Investigation.STATUSES.CREATED.value,
            for_organization=False,
        )

        # A small job tree on inv_created: root1 -> child1 (different status) + root2,
        # so the tree has nesting and the status breakdown spans >= 2 statuses.
        self.root1 = Job.objects.create(
            user=self.user,
            analyzable=self.analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
        )
        self.child1 = self.root1.add_child(
            user=self.user,
            analyzable=self.analyzable,
            status=Job.STATUSES.FAILED,
        )
        self.root2 = Job.objects.create(
            user=self.user,
            analyzable=self.analyzable,
            status=Job.STATUSES.RUNNING,
        )
        self.inv_created.jobs.add(self.root1, self.root2)

        tools_by_name = {t.name: t for t in build_tools(user=self.user)}
        self.list_investigations = tools_by_name["list_investigations"]
        self.get_investigation_tree = tools_by_name["get_investigation_tree"]
        self.summarize_investigation = tools_by_name["summarize_investigation"]

    def tearDown(self):
        Job.objects.filter(user__in=[self.user, self.org_member]).delete()
        Investigation.objects.filter(owner__in=[self.user, self.org_member]).delete()
        Membership.objects.filter(organization=self.org).delete()
        self.org.delete()

    def test_list_investigations_status_filter(self):
        data = json.loads(self.list_investigations.invoke({"status": "running"}))
        self.assertEqual(data["errors"], [])
        ids = [i["id"] for i in data["investigations"]]
        self.assertIn(self.inv_running.pk, ids)
        self.assertNotIn(self.inv_created.pk, ids)

    def test_list_investigations_name_filter(self):
        data = json.loads(self.list_investigations.invoke({"query": "beta"}))
        ids = [i["id"] for i in data["investigations"]]
        self.assertEqual(ids, [self.inv_running.pk])

    def test_list_investigations_limit(self):
        data = json.loads(self.list_investigations.invoke({"limit": 1}))
        self.assertEqual(len(data["investigations"]), 1)

    def test_list_investigations_isolation_and_org_shared(self):
        data = json.loads(self.list_investigations.invoke({}))
        ids = [i["id"] for i in data["investigations"]]
        # owned + org-shared are visible
        self.assertIn(self.inv_created.pk, ids)
        self.assertIn(self.inv_running.pk, ids)
        self.assertIn(self.inv_org_shared.pk, ids)
        # another member's private investigation is NOT visible
        self.assertNotIn(self.inv_private.pk, ids)

    def test_list_investigations_invalid_status(self):
        data = json.loads(self.list_investigations.invoke({"status": "bogus"}))
        # invalid status is reported and the filter is ignored (results still returned)
        self.assertTrue(data["errors"])
        self.assertIn("Unknown status", data["errors"][0])
        ids = [i["id"] for i in data["investigations"]]
        self.assertIn(self.inv_created.pk, ids)

    def test_list_investigations_limit_over_cap_reports_error(self):
        result = self.list_investigations.invoke({"limit": 100})
        data = json.loads(result)
        self.assertTrue(any("maximum 50" in e for e in data["errors"]))

    def test_get_investigation_tree_structure(self):
        data = json.loads(self.get_investigation_tree.invoke({"investigation_id": self.inv_created.pk}))
        self.assertEqual(data["errors"], [])
        tree = data["investigation"]
        self.assertEqual(tree["id"], self.inv_created.pk)
        nodes = {n["id"]: n for n in tree["jobs"]}
        self.assertIn(self.root1.pk, nodes)
        self.assertIn(self.root2.pk, nodes)
        self.assertEqual(nodes[self.root1.pk]["observable"], "inv.example.com")
        child_ids = [c["id"] for c in nodes[self.root1.pk]["children"]]
        self.assertEqual(child_ids, [self.child1.pk])
        self.assertEqual(nodes[self.root2.pk]["children"], [])

    def test_get_investigation_tree_not_visible(self):
        data = json.loads(self.get_investigation_tree.invoke({"investigation_id": self.inv_private.pk}))
        self.assertIsNone(data["investigation"])
        self.assertTrue(data["errors"])
        self.assertIn("not found or not accessible", data["errors"][0])

    def test_summarize_investigation_breakdown(self):
        summary = json.loads(self.summarize_investigation.invoke({"investigation_id": self.inv_created.pk}))[
            "summary"
        ]
        self.assertIn(f"Investigation #{self.inv_created.pk}", summary)
        self.assertIn("Total jobs : 3", summary)
        # breakdown must span the distinct job statuses, not just one branch
        self.assertIn(Job.STATUSES.REPORTED_WITHOUT_FAILS.value, summary)
        self.assertIn(Job.STATUSES.FAILED.value, summary)
        self.assertIn(Job.STATUSES.RUNNING.value, summary)

    def test_summarize_investigation_not_visible(self):
        data = json.loads(self.summarize_investigation.invoke({"investigation_id": self.inv_private.pk}))
        self.assertIsNone(data["summary"])
        self.assertTrue(data["errors"])
