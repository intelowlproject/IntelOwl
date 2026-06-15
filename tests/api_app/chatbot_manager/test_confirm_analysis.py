# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.chatbot_manager.pending_action import create_pending_analysis
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.user.models import User

_APPLY_ASYNC = "intel_owl.tasks.job_pipeline.apply_async"
_URL = "/api/chatbot/analysis/confirm"


@override_settings(CHATBOT_PENDING_ACTION_TTL=600)
class ConfirmAnalysisViewTestCase(APITestCase):
    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="confirm_user")
        self.other, _ = User.objects.get_or_create(username="confirm_other")
        self.analyzer = AnalyzerConfig.objects.get(name="Tranco")  # seeded, free, supports domain
        # A playbook owned by another user and NOT shared -> invisible to self.user (TOCTOU guard test).
        self.pb_private_other = PlaybookConfig.objects.create(
            name="confirm_pb_private",
            description="t",
            type=["domain"],
            owner=self.other,
            for_organization=False,
            starting=True,
        )
        self.pb_private_other.analyzers.set([self.analyzer])
        self.client.force_authenticate(self.user)
        self.payload = {
            "observable_name": "example.com",
            "tlp": "CLEAR",
            "playbook": "",
            "analyzers": "Tranco",
        }

    def tearDown(self):
        Job.objects.filter(user__in=[self.user, self.other]).delete()
        PlaybookConfig.objects.filter(owner=self.other).delete()

    @patch(_APPLY_ASYNC)
    def test_confirm_launches_valid_pending(self, mock_apply):
        pending_id = create_pending_analysis(self.user.id, self.payload)
        resp = self.client.post(_URL, {"pending_id": pending_id}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.json()["errors"], [])
        self.assertIsNotNone(resp.json()["job"])
        mock_apply.assert_called_once()

    @patch(_APPLY_ASYNC)
    def test_launched_job_owned_by_requesting_user(self, mock_apply):
        pending_id = create_pending_analysis(self.user.id, self.payload)
        job_id = self.client.post(_URL, {"pending_id": pending_id}, format="json").json()["job"]["id"]
        self.assertEqual(Job.objects.get(pk=job_id).user, self.user)

    @patch(_APPLY_ASYNC)
    def test_confirm_is_one_shot(self, mock_apply):
        pending_id = create_pending_analysis(self.user.id, self.payload)
        self.client.post(_URL, {"pending_id": pending_id}, format="json")
        resp = self.client.post(_URL, {"pending_id": pending_id}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_410_GONE)
        mock_apply.assert_called_once()

    @patch(_APPLY_ASYNC)
    def test_confirm_rejects_other_users_pending(self, mock_apply):
        pending_id = create_pending_analysis(self.other.id, self.payload)
        resp = self.client.post(_URL, {"pending_id": pending_id}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_410_GONE)
        mock_apply.assert_not_called()

    @patch(_APPLY_ASYNC)
    def test_confirm_unknown_id(self, mock_apply):
        resp = self.client.post(_URL, {"pending_id": "deadbeef"}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_410_GONE)
        mock_apply.assert_not_called()

    @patch(_APPLY_ASYNC)
    def test_confirm_rejects_playbook_no_longer_visible(self, mock_apply):
        # TOCTOU guard: a pending whose playbook is not visible to the user at confirm time is
        # refused (the confirm view re-applies the same visible_for_user guard as the preview tool).
        pending_id = create_pending_analysis(
            self.user.id,
            {
                "observable_name": "example.com",
                "tlp": "CLEAR",
                "playbook": self.pb_private_other.name,
                "analyzers": "",
            },
        )
        resp = self.client.post(_URL, {"pending_id": pending_id}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(resp.json()["errors"])
        mock_apply.assert_not_called()

    def test_confirm_requires_auth(self):
        self.client.force_authenticate(None)
        resp = self.client.post(_URL, {"pending_id": "x"}, format="json")
        self.assertIn(resp.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))
