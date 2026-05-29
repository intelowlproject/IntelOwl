# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime

from django.test import TestCase, override_settings
from django.utils.timezone import now

from api_app.chatbot_manager.models import ChatMessage, ChatSession
from api_app.chatbot_manager.tasks import delete_old_chat_sessions
from certego_saas.apps.user.models import User


@override_settings(CHATBOT_MESSAGE_RETENTION_DAYS=30)
class DeleteOldChatSessionsTestCase(TestCase):
    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chatbot_retention_user")

    def _session_with_last_message(self, days_old):
        session = ChatSession.objects.create(user=self.user)
        ChatMessage.objects.create(
            session=session,
            role=ChatMessage.Role.USER,
            content="hi",
            timestamp=now() - datetime.timedelta(days=days_old),
        )
        return session

    def test_deletes_stale_session_and_its_messages(self):
        session = self._session_with_last_message(days_old=40)
        message_pks = list(session.messages.values_list("pk", flat=True))

        self.assertEqual(delete_old_chat_sessions(), 1)
        self.assertFalse(ChatSession.objects.filter(pk=session.pk).exists())
        # CASCADE: the session's messages must be gone too
        self.assertFalse(ChatMessage.objects.filter(pk__in=message_pks).exists())

    def test_keeps_recent_session(self):
        session = self._session_with_last_message(days_old=5)

        self.assertEqual(delete_old_chat_sessions(), 0)
        self.assertTrue(ChatSession.objects.filter(pk=session.pk).exists())

    def test_boundary_around_cutoff(self):
        # retention = 30 days: __lt cutoff means strictly older than 30 days is stale.
        stale = self._session_with_last_message(days_old=31)
        fresh = self._session_with_last_message(days_old=29)

        self.assertEqual(delete_old_chat_sessions(), 1)
        self.assertFalse(ChatSession.objects.filter(pk=stale.pk).exists())
        self.assertTrue(ChatSession.objects.filter(pk=fresh.pk).exists())

    def test_empty_session_uses_created_at(self):
        # No messages -> last_activity falls back to created_at (the Coalesce branch).
        old_empty = ChatSession.objects.create(user=self.user, created_at=now() - datetime.timedelta(days=40))
        recent_empty = ChatSession.objects.create(
            user=self.user, created_at=now() - datetime.timedelta(days=5)
        )

        self.assertEqual(delete_old_chat_sessions(), 1)
        self.assertFalse(ChatSession.objects.filter(pk=old_empty.pk).exists())
        self.assertTrue(ChatSession.objects.filter(pk=recent_empty.pk).exists())

    def test_old_session_with_recent_message_is_kept(self):
        # Long-running session: created long ago but still active. last_activity must come
        # from the most recent message, NOT created_at, so it must survive.
        session = ChatSession.objects.create(user=self.user, created_at=now() - datetime.timedelta(days=40))
        ChatMessage.objects.create(
            session=session,
            role=ChatMessage.Role.USER,
            content="still here",
            timestamp=now() - datetime.timedelta(days=2),
        )

        self.assertEqual(delete_old_chat_sessions(), 0)
        self.assertTrue(ChatSession.objects.filter(pk=session.pk).exists())
