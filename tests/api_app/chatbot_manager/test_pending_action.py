# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.test import SimpleTestCase, override_settings

from api_app.chatbot_manager.pending_action import (
    consume_pending_analysis,
    create_pending_analysis,
)

TEST_CACHES = {
    "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
    "chatbot_pending_action": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "pending-test",
    },
}
PAYLOAD = {"observable_name": "example.com", "tlp": "CLEAR", "playbook": "", "analyzers": "Tranco"}


@override_settings(CACHES=TEST_CACHES, CHATBOT_PENDING_ACTION_TTL=600)
class PendingActionTestCase(SimpleTestCase):
    def test_create_then_consume_returns_payload(self):
        pending_id = create_pending_analysis(7, PAYLOAD)
        self.assertTrue(pending_id)
        self.assertEqual(consume_pending_analysis(7, pending_id), PAYLOAD)

    def test_consume_is_one_shot(self):
        pending_id = create_pending_analysis(7, PAYLOAD)
        consume_pending_analysis(7, pending_id)
        self.assertIsNone(consume_pending_analysis(7, pending_id))

    def test_consume_rejects_other_user(self):
        pending_id = create_pending_analysis(7, PAYLOAD)
        self.assertIsNone(consume_pending_analysis(99, pending_id))

    def test_consume_unknown_id_returns_none(self):
        self.assertIsNone(consume_pending_analysis(7, "deadbeef"))
