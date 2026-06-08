# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
from unittest.mock import patch

from django.test import TestCase

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.chatbot_manager.agent.tools import build_tools
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from certego_saas.apps.user.models import User

# The trigger lives at `intel_owl.tasks.job_pipeline.apply_async`; patching it lets us assert
# whether an analysis would have been launched without running Celery (the create path imports
# `job_pipeline` from this module, so the patched attribute is the one it calls).
_APPLY_ASYNC = "intel_owl.tasks.job_pipeline.apply_async"


class AnalyzeObservableToolTestCase(TestCase):
    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="analyze_obs_user")
        # Another member of the same org: used to build a playbook that is private to them (i.e.
        # NOT visible to self.user) for the isolation test.
        self.org_member, _ = User.objects.get_or_create(username="analyze_obs_org_member")
        self.org, _ = Organization.objects.get_or_create(name="analyze obs organization")
        Membership.objects.get_or_create(user=self.user, organization=self.org, is_owner=True)
        Membership.objects.get_or_create(user=self.org_member, organization=self.org, is_owner=False)

        # A real seeded, free (no API key) observable analyzer that supports `domain` and is runnable
        # at TLP CLEAR (max_tlp AMBER). Constructing one would need a PythonModule FK.
        self.analyzer = AnalyzerConfig.objects.get(name="Tranco")

        # Owned by self.user -> visible: passes the tool's visibility guard.
        self.pb_owned = PlaybookConfig.objects.create(
            name="analyze_obs_pb_owned", description="t", type=["domain"], owner=self.user, starting=True
        )
        self.pb_owned.analyzers.set([self.analyzer])
        # Owned by another member, NOT org-shared -> invisible to self.user.
        self.pb_private_other = PlaybookConfig.objects.create(
            name="analyze_obs_pb_private",
            description="t",
            type=["domain"],
            owner=self.org_member,
            for_organization=False,
            starting=True,
        )
        self.pb_private_other.analyzers.set([self.analyzer])

        self.analyze_observable = {t.name: t for t in build_tools(user=self.user)}["analyze_observable"]

    def tearDown(self):
        Job.objects.filter(user__in=[self.user, self.org_member]).delete()
        PlaybookConfig.objects.filter(owner__in=[self.user, self.org_member]).delete()
        Membership.objects.filter(organization=self.org).delete()
        self.org.delete()

    @patch(_APPLY_ASYNC)
    def test_preview_does_not_trigger(self, mock_apply):
        # confirm defaults to False -> preview only: a plan is returned and NOTHING is launched.
        # This is the core safety guarantee of the action tool.
        data = json.loads(
            self.analyze_observable.invoke({"observable_name": "example.com", "analyzers": "Tranco"})
        )
        self.assertEqual(data["errors"], [])
        self.assertTrue(data["confirmation_required"])
        self.assertIsNotNone(data["plan"])
        self.assertIsNone(data["job"])
        self.assertEqual(data["plan"]["classification"], "domain")
        self.assertIn("Tranco", data["plan"]["analyzers"])
        mock_apply.assert_not_called()

    @patch(_APPLY_ASYNC)
    def test_confirm_triggers_once(self, mock_apply):
        data = json.loads(
            self.analyze_observable.invoke(
                {"observable_name": "example.com", "analyzers": "Tranco", "confirm": True}
            )
        )
        self.assertEqual(data["errors"], [])
        self.assertFalse(data["confirmation_required"])
        self.assertIsNone(data["plan"])
        self.assertIsNotNone(data["job"])
        self.assertEqual(data["job"]["observable_name"], "example.com")
        self.assertFalse(data["reused"])  # fresh observable -> a new job, not a reused one
        mock_apply.assert_called_once()

    @patch(_APPLY_ASYNC)
    def test_created_job_owned_by_requesting_user(self, mock_apply):
        # Multi-tenancy: the launched Job is created under the closured user, never widened.
        data = json.loads(
            self.analyze_observable.invoke(
                {"observable_name": "example.com", "analyzers": "Tranco", "confirm": True}
            )
        )
        job = Job.objects.get(pk=data["job"]["id"])
        self.assertEqual(job.user, self.user)

    @patch(_APPLY_ASYNC)
    def test_dedup_reuses_recent_job_on_second_confirm(self, mock_apply):
        # Default scan_mode (CHECK_PREVIOUS_ANALYSIS): a second confirmed call for the same observable
        # reuses the recent job instead of launching a duplicate -> apply_async fires only once and the
        # second result is flagged `reused` with the same job id.
        args = {"observable_name": "example.com", "analyzers": "Tranco", "confirm": True}
        first = json.loads(self.analyze_observable.invoke(args))
        second = json.loads(self.analyze_observable.invoke(args))
        self.assertFalse(first["reused"])
        self.assertTrue(second["reused"])
        self.assertEqual(first["job"]["id"], second["job"]["id"])
        mock_apply.assert_called_once()

    @patch(_APPLY_ASYNC)
    def test_private_ip_refused(self, mock_apply):
        # The serializer's IP guardrail rejects a private IP during validation -> even with
        # confirm=True the request never reaches the trigger.
        data = json.loads(
            self.analyze_observable.invoke(
                {"observable_name": "10.0.0.1", "analyzers": "Classic_DNS", "confirm": True}
            )
        )
        self.assertTrue(data["errors"])
        self.assertIsNone(data["job"])
        mock_apply.assert_not_called()

    @patch(_APPLY_ASYNC)
    def test_unknown_analyzer_refused(self, mock_apply):
        # An analyzer name the serializer can't resolve -> validation error, nothing triggered.
        data = json.loads(
            self.analyze_observable.invoke(
                {"observable_name": "example.com", "analyzers": "NotARealAnalyzer", "confirm": True}
            )
        )
        self.assertTrue(data["errors"])
        self.assertIsNone(data["job"])
        mock_apply.assert_not_called()

    @patch(_APPLY_ASYNC)
    def test_playbook_not_visible_refused(self, mock_apply):
        # Isolation must-fix: another member's PRIVATE playbook must never resolve. The reused
        # serializer would look it up via PlaybookConfig.objects.all(); the tool's visible_for_user
        # guard rejects it first, so its existence/composition is never leaked into a plan.
        data = json.loads(
            self.analyze_observable.invoke(
                {"observable_name": "example.com", "playbook": self.pb_private_other.name, "confirm": True}
            )
        )
        self.assertTrue(any("not found or not visible" in e for e in data["errors"]))
        self.assertIsNone(data["plan"])
        self.assertIsNone(data["job"])
        mock_apply.assert_not_called()

    @patch(_APPLY_ASYNC)
    def test_visible_playbook_preview(self, mock_apply):
        # A playbook owned by the user passes the guard and previews with its name in the plan.
        data = json.loads(
            self.analyze_observable.invoke({"observable_name": "example.com", "playbook": self.pb_owned.name})
        )
        self.assertEqual(data["errors"], [])
        self.assertTrue(data["confirmation_required"])
        self.assertEqual(data["plan"]["playbook"], self.pb_owned.name)
        mock_apply.assert_not_called()
