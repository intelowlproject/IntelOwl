# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
from uuid import uuid4

from django.test import TestCase

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.constants import TypeChoices
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.chatbot_manager.agent.tools import build_tools
from api_app.chatbot_manager.agent.tools._common import MAX_RESULTS, clamp_limit
from api_app.choices import Classification, ScanMode
from api_app.data_model_manager.models import DomainDataModel
from api_app.investigations_manager.models import Investigation
from api_app.models import Job, OrganizationPluginConfiguration
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from certego_saas.apps.user.models import User


class SearchJobsToolTestCase(TestCase):
    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chatbot_tool_user")
        self.other_user, _ = User.objects.get_or_create(username="chatbot_other_user")
        self.analyzable, _ = Analyzable.objects.get_or_create(
            name="malware.example.com",
            classification=Classification.DOMAIN,
        )
        self.job = Job.objects.create(
            user=self.user,
            analyzable=self.analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            tlp="GREEN",
        )
        self.other_job = Job.objects.create(
            user=self.other_user,
            analyzable=self.analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            tlp="GREEN",
        )
        tools = build_tools(user=self.user)
        tools_by_name = {t.name: t for t in tools}
        self.search_jobs = tools_by_name["search_jobs"]
        self.get_job_details = tools_by_name["get_job_details"]
        self.summarize_job = tools_by_name["summarize_job"]

    def test_search_jobs_returns_matching(self):
        result = self.search_jobs.invoke({"query": "malware.example.com"})
        data = json.loads(result)
        self.assertEqual(data["errors"], [])
        self.assertEqual(len(data["jobs"]), 1)
        self.assertEqual(data["jobs"][0]["id"], self.job.pk)

    def test_search_jobs_respects_user_isolation(self):
        other_tools = build_tools(user=self.other_user)
        search = {t.name: t for t in other_tools}["search_jobs"]
        result = search.invoke({"query": "malware.example.com"})
        data = json.loads(result)
        ids = [d["id"] for d in data["jobs"]]
        self.assertIn(self.other_job.pk, ids)
        self.assertNotIn(self.job.pk, ids)

    def test_search_jobs_no_results(self):
        result = self.search_jobs.invoke({"query": "nonexistent999"})
        data = json.loads(result)
        self.assertEqual(data["errors"], [])
        self.assertEqual(data["jobs"], [])

    def test_get_job_details_returns_data(self):
        result = self.get_job_details.invoke({"job_id": self.job.pk})
        data = json.loads(result)
        self.assertEqual(data["errors"], [])
        self.assertEqual(data["job"]["id"], self.job.pk)
        self.assertIn("observable_name", data["job"])
        self.assertIn("status", data["job"])

    def test_get_job_details_forbidden_other_user(self):
        result = self.get_job_details.invoke({"job_id": self.other_job.pk})
        data = json.loads(result)
        self.assertIsNone(data["job"])
        self.assertTrue(data["errors"])
        self.assertIn("not found or not accessible", data["errors"][0])

    def test_summarize_job_formats_output(self):
        result = self.summarize_job.invoke({"job_id": self.job.pk})
        data = json.loads(result)
        self.assertEqual(data["errors"], [])
        self.assertIn(f"Job #{self.job.pk}", data["summary"])
        self.assertIn("malware.example.com", data["summary"])
        self.assertIn("Status", data["summary"])

    def test_summarize_job_failed_reports_use_report_status(self):
        # Regression: analyzer report status uses ReportStatus (uppercase). Only the
        # non-SUCCESS report must show up under "Failed".
        config_ok, config_ko = list(AnalyzerConfig.objects.all()[:2])
        AnalyzerReport.objects.create(
            report={},
            job=self.job,
            config=config_ok,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid4()),
            parameters={},
        )
        AnalyzerReport.objects.create(
            report={},
            job=self.job,
            config=config_ko,
            status=AnalyzerReport.STATUSES.FAILED.value,
            task_id=str(uuid4()),
            parameters={},
        )
        summary = json.loads(self.summarize_job.invoke({"job_id": self.job.pk}))["summary"]
        self.assertIn(config_ko.name, summary)
        self.assertNotIn(config_ok.name, summary)

    def tearDown(self):
        Job.objects.filter(user__in=[self.user, self.other_user]).delete()


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


class DataModelToolTestCase(TestCase):
    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="dm_tool_user")
        self.other_user, _ = User.objects.get_or_create(username="dm_tool_other_user")
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
        # Another user's job (must stay inaccessible).
        self.other_job = Job.objects.create(
            user=self.other_user,
            analyzable=self.analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
        )
        self.get_data_model = {t.name: t for t in build_tools(user=self.user)}["get_data_model"]

    def tearDown(self):
        Job.objects.filter(user__in=[self.user, self.other_user]).delete()
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


class ListAnalyzersToolTestCase(TestCase):
    def setUp(self):
        self.org_user, _ = User.objects.get_or_create(username="list_analyzers_org_user")
        self.outsider, _ = User.objects.get_or_create(username="list_analyzers_outsider")
        self.org, _ = Organization.objects.get_or_create(name="list analyzers organization")
        Membership.objects.get_or_create(user=self.org_user, organization=self.org, is_owner=True)

        # A real seeded observable analyzer (constructing one would need a PythonModule FK).
        self.analyzer = (
            AnalyzerConfig.objects.filter(
                type=TypeChoices.OBSERVABLE,
                observable_supported__contains=["domain"],
                disabled=False,
            )
            .order_by("name")
            .first()
        )
        self.assertIsNotNone(self.analyzer, "expected a seeded observable analyzer supporting 'domain'")

        # Disable it for self.org: the per-user `runnable` flag must flip to False, but the
        # analyzer must still be listed (analyzer configs are global, non-sensitive).
        self.org_disable = OrganizationPluginConfiguration.objects.create(
            config=self.analyzer, organization=self.org, disabled=True
        )

        self.list_analyzers = {t.name: t for t in build_tools(user=self.org_user)}["list_analyzers"]

    def tearDown(self):
        self.org_disable.delete()
        Membership.objects.filter(organization=self.org).delete()
        self.org.delete()

    def test_list_analyzers_filters_by_observable_type(self):
        data = json.loads(self.list_analyzers.invoke({"observable_type": "domain"}))
        self.assertEqual(data["errors"], [])
        self.assertTrue(data["analyzers"])
        # every returned analyzer supports the requested observable type
        for analyzer in data["analyzers"]:
            self.assertIn("domain", analyzer["observable_supported"])
        names = [a["name"] for a in data["analyzers"]]
        self.assertIn(self.analyzer.name, names)

    def test_list_analyzers_unknown_observable_type(self):
        data = json.loads(self.list_analyzers.invoke({"observable_type": "bogus"}))
        # invalid type is reported and the filter is ignored (results still returned)
        self.assertTrue(data["errors"])
        self.assertIn("Unknown observable_type", data["errors"][0])
        self.assertTrue(data["analyzers"])

    def test_list_analyzers_limit(self):
        data = json.loads(self.list_analyzers.invoke({"limit": 1}))
        self.assertEqual(len(data["analyzers"]), 1)

    def test_list_analyzers_limit_clamps_to_max(self):
        # An over-cap limit from the LLM is clamped to MAX_RESULTS (untrusted arg): the seeded
        # observable analyzers exceed the cap, so the result is capped, never the requested 999.
        # The clamp is surfaced in `errors` so a truncated list isn't silent.
        data = json.loads(self.list_analyzers.invoke({"limit": 999}))
        self.assertLessEqual(len(data["analyzers"]), MAX_RESULTS)
        self.assertTrue(any("exceeds the maximum" in e for e in data["errors"]))

    def test_list_analyzers_org_disabled_runnable_flag(self):
        # Deterministic, one-directional isolation check: an analyzer disabled for the user's
        # organization comes back with runnable=False AND is still present in the list (it is
        # not hidden -- list_analyzers lists, it does not filter on runnable). We do NOT assert
        # the contrasting runnable=True for an outsider, because `runnable` also folds in
        # configured+healthy, which a key-based analyzer lacks on a test deploy without keys.
        rows = {
            a["name"]: a
            for a in json.loads(self.list_analyzers.invoke({"observable_type": "domain"}))["analyzers"]
        }
        self.assertIn(self.analyzer.name, rows)
        self.assertFalse(rows[self.analyzer.name]["runnable"])

        # The same analyzer is still listed for an unaffiliated user (global, non-sensitive).
        outsider_tool = {t.name: t for t in build_tools(user=self.outsider)}["list_analyzers"]
        outsider_names = [
            a["name"] for a in json.loads(outsider_tool.invoke({"observable_type": "domain"}))["analyzers"]
        ]
        self.assertIn(self.analyzer.name, outsider_names)


class RecommendPlaybookToolTestCase(TestCase):
    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="recommend_pb_user")
        # Another member of the same org: used to test org-shared vs private visibility.
        self.org_member, _ = User.objects.get_or_create(username="recommend_pb_org_member")
        self.org, _ = Organization.objects.get_or_create(name="recommend pb organization")
        Membership.objects.get_or_create(user=self.user, organization=self.org, is_owner=True)
        Membership.objects.get_or_create(user=self.org_member, organization=self.org, is_owner=False)

        self.pb_owned = PlaybookConfig.objects.create(
            name="recommend_pb_owned", description="t", type=["ip"], owner=self.user, starting=True
        )
        # Owned by another member of the same org and shared at org level -> visible.
        self.pb_org_shared = PlaybookConfig.objects.create(
            name="recommend_pb_org_shared",
            description="t",
            type=["ip"],
            owner=self.org_member,
            for_organization=True,
            starting=True,
        )
        # Owned by another member but NOT shared -> must stay invisible to self.user.
        self.pb_private_other = PlaybookConfig.objects.create(
            name="recommend_pb_private_other",
            description="t",
            type=["ip"],
            owner=self.org_member,
            for_organization=False,
            starting=True,
        )
        # Not directly launchable -> must not be recommended. A non-starting playbook must force
        # new analysis with no check time (model clean()), which create() enforces.
        self.pb_not_starting = PlaybookConfig.objects.create(
            name="recommend_pb_not_starting",
            description="t",
            type=["ip"],
            owner=self.user,
            starting=False,
            scan_mode=ScanMode.FORCE_NEW_ANALYSIS.value,
            scan_check_time=None,
        )
        # Disabled -> must not be recommended.
        self.pb_disabled = PlaybookConfig.objects.create(
            name="recommend_pb_disabled",
            description="t",
            type=["ip"],
            owner=self.user,
            starting=True,
            disabled=True,
        )
        # Different classification -> must not match an ip observable.
        self.pb_domain = PlaybookConfig.objects.create(
            name="recommend_pb_domain", description="t", type=["domain"], owner=self.user, starting=True
        )

        self.recommend_playbook = {t.name: t for t in build_tools(user=self.user)}["recommend_playbook"]

    def tearDown(self):
        PlaybookConfig.objects.filter(owner__in=[self.user, self.org_member]).delete()
        Membership.objects.filter(organization=self.org).delete()
        self.org.delete()

    def test_recommend_playbook_derives_classification_from_observable(self):
        data = json.loads(self.recommend_playbook.invoke({"observable_name": "8.8.8.8"}))
        self.assertEqual(data["errors"], [])
        names = [p["name"] for p in data["playbooks"]]
        # 8.8.8.8 is classified as ip -> the ip playbook matches, the domain one does not
        self.assertIn(self.pb_owned.name, names)
        self.assertNotIn(self.pb_domain.name, names)

    def test_recommend_playbook_explicit_classification(self):
        data = json.loads(self.recommend_playbook.invoke({"classification": "ip"}))
        self.assertEqual(data["errors"], [])
        names = [p["name"] for p in data["playbooks"]]
        self.assertIn(self.pb_owned.name, names)

    def test_recommend_playbook_invalid_classification(self):
        data = json.loads(self.recommend_playbook.invoke({"classification": "bogus"}))
        self.assertTrue(data["errors"])
        self.assertIn("Unknown classification", data["errors"][0])
        self.assertEqual(data["playbooks"], [])

    def test_recommend_playbook_requires_input(self):
        data = json.loads(self.recommend_playbook.invoke({}))
        self.assertTrue(data["errors"])
        self.assertEqual(data["playbooks"], [])

    def test_recommend_playbook_only_starting_and_enabled(self):
        names = [
            p["name"]
            for p in json.loads(self.recommend_playbook.invoke({"classification": "ip"}))["playbooks"]
        ]
        self.assertIn(self.pb_owned.name, names)
        self.assertNotIn(self.pb_not_starting.name, names)
        self.assertNotIn(self.pb_disabled.name, names)

    def test_recommend_playbook_visibility_isolation(self):
        names = [
            p["name"]
            for p in json.loads(self.recommend_playbook.invoke({"classification": "ip"}))["playbooks"]
        ]
        # owned + org-shared are visible
        self.assertIn(self.pb_owned.name, names)
        self.assertIn(self.pb_org_shared.name, names)
        # another member's private playbook is NOT visible
        self.assertNotIn(self.pb_private_other.name, names)

    def test_recommend_playbook_limit(self):
        # Two visible, starting, enabled ip playbooks match (owned + org-shared); the cap must
        # trim the result to the requested size.
        all_matches = json.loads(self.recommend_playbook.invoke({"classification": "ip"}))["playbooks"]
        self.assertGreaterEqual(len(all_matches), 2)
        capped = json.loads(self.recommend_playbook.invoke({"classification": "ip", "limit": 1}))
        self.assertEqual(len(capped["playbooks"]), 1)

    def test_recommend_playbook_limit_clamp_warns(self):
        # An over-cap limit is clamped to MAX_RESULTS and the clamp is surfaced in `errors`,
        # regardless of how many playbooks actually match (999 > 50 always warns).
        data = json.loads(self.recommend_playbook.invoke({"classification": "ip", "limit": 999}))
        self.assertTrue(any("exceeds the maximum" in e for e in data["errors"]))


class ClampLimitHelperTestCase(TestCase):
    """Unit tests for the shared `clamp_limit` helper used by the analyzer/playbook tools."""

    def test_within_range_passes_through(self):
        errors = []
        self.assertEqual(clamp_limit(10, errors), 10)
        self.assertEqual(errors, [])

    def test_over_cap_clamps_and_warns(self):
        errors = []
        self.assertEqual(clamp_limit(999, errors), MAX_RESULTS)
        self.assertTrue(any("exceeds the maximum" in e for e in errors))

    def test_below_one_clamps_up_silently(self):
        # A non-positive limit is bounded up to 1 without a warning (only over-cap is worth one).
        errors = []
        self.assertEqual(clamp_limit(0, errors), 1)
        self.assertEqual(clamp_limit(-5, errors), 1)
        self.assertEqual(errors, [])
