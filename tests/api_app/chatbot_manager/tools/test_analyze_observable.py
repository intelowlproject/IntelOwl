# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
from unittest.mock import patch

from django.test import TestCase, override_settings

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


@override_settings(CHATBOT_PENDING_ACTION_TTL=600)
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
    def test_preview_returns_plan_and_pending_id_without_launching(self, mock_apply):
        data = json.loads(
            self.analyze_observable.invoke({"observable_name": "example.com", "analyzers": "Tranco"})
        )
        self.assertEqual(data["errors"], [])
        self.assertIsNotNone(data["plan"])
        self.assertEqual(data["plan"]["classification"], "domain")
        self.assertIn("Tranco", data["plan"]["analyzers"])
        self.assertTrue(data["pending_id"])
        mock_apply.assert_not_called()  # the tool NEVER launches

    @patch(_APPLY_ASYNC)
    def test_preview_mints_a_consumable_pending_record(self, mock_apply):
        from api_app.chatbot_manager.pending_action import consume_pending_analysis

        data = json.loads(
            self.analyze_observable.invoke({"observable_name": "example.com", "analyzers": "Tranco"})
        )
        payload = consume_pending_analysis(self.user.id, data["pending_id"])
        self.assertEqual(payload["observable_name"], "example.com")
        self.assertEqual(payload["analyzers"], "Tranco")
        mock_apply.assert_not_called()

    @patch(_APPLY_ASYNC)
    def test_private_ip_refused_at_preview(self, mock_apply):
        data = json.loads(
            self.analyze_observable.invoke({"observable_name": "10.0.0.1", "analyzers": "Classic_DNS"})
        )
        self.assertTrue(data["errors"])
        self.assertIsNone(data["plan"])
        self.assertIsNone(data["pending_id"])
        mock_apply.assert_not_called()

    @patch(_APPLY_ASYNC)
    def test_unknown_analyzer_refused_at_preview(self, mock_apply):
        data = json.loads(
            self.analyze_observable.invoke(
                {"observable_name": "example.com", "analyzers": "NotARealAnalyzer"}
            )
        )
        self.assertTrue(data["errors"])
        self.assertIsNone(data["pending_id"])
        mock_apply.assert_not_called()

    @patch(_APPLY_ASYNC)
    def test_playbook_not_visible_refused(self, mock_apply):
        data = json.loads(
            self.analyze_observable.invoke(
                {"observable_name": "example.com", "playbook": self.pb_private_other.name}
            )
        )
        self.assertTrue(any("not found or not visible" in e for e in data["errors"]))
        self.assertIsNone(data["plan"])
        self.assertIsNone(data["pending_id"])
        mock_apply.assert_not_called()

    @patch(_APPLY_ASYNC)
    def test_visible_playbook_preview(self, mock_apply):
        data = json.loads(
            self.analyze_observable.invoke({"observable_name": "example.com", "playbook": self.pb_owned.name})
        )
        self.assertEqual(data["errors"], [])
        self.assertEqual(data["plan"]["playbook"], self.pb_owned.name)
        self.assertTrue(data["pending_id"])
        mock_apply.assert_not_called()
