# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

from rest_framework import status
from rest_framework.test import APITestCase

from api_app.chatbot_manager.models import ChatMessage, ChatSession
from certego_saas.apps.user.models import User

MOCK_AGENT_OUTPUT = {"output": "Here are your recent jobs."}


class ChatSessionViewSetTestCase(APITestCase):
    URL = "/api/chatbot/sessions"
    MESSAGE_URL = "/api/chatbot/sessions/message"

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chatbot_view_user")
        self.client.force_authenticate(user=self.user)

    @patch(
        "api_app.chatbot_manager.views.build_agent_executor",
        return_value=MagicMock(invoke=MagicMock(return_value=MOCK_AGENT_OUTPUT)),
    )
    def test_message_creates_session_when_none_provided(self, mock_executor):
        response = self.client.post(
            self.MESSAGE_URL,
            data={"message": "Show me recent jobs"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("session_id", data)
        self.assertIn("response", data)
        self.assertIn("message_id", data)
        self.assertEqual(data["response"], MOCK_AGENT_OUTPUT["output"])
        self.assertTrue(ChatSession.objects.filter(pk=data["session_id"]).exists())

    @patch(
        "api_app.chatbot_manager.views.build_agent_executor",
        return_value=MagicMock(invoke=MagicMock(return_value=MOCK_AGENT_OUTPUT)),
    )
    def test_message_reuses_existing_session(self, mock_executor):
        session = ChatSession.objects.create(user=self.user)
        response = self.client.post(
            self.MESSAGE_URL,
            data={"message": "Hello", "session_id": session.pk},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["session_id"], session.pk)

    @patch(
        "api_app.chatbot_manager.views.build_agent_executor",
        return_value=MagicMock(invoke=MagicMock(return_value=MOCK_AGENT_OUTPUT)),
    )
    def test_message_saves_user_and_assistant_messages(self, mock_executor):
        response = self.client.post(
            self.MESSAGE_URL,
            data={"message": "Hello"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        session_id = response.json()["session_id"]
        msgs = list(ChatMessage.objects.filter(session_id=session_id).order_by("timestamp"))
        self.assertEqual(len(msgs), 2)
        self.assertEqual(msgs[0].role, ChatMessage.Role.USER)
        self.assertEqual(msgs[0].content, "Hello")
        self.assertEqual(msgs[1].role, ChatMessage.Role.ASSISTANT)
        self.assertEqual(msgs[1].content, MOCK_AGENT_OUTPUT["output"])

    def test_message_returns_404_for_other_users_session(self):
        other_user, _ = User.objects.get_or_create(username="chatbot_other_view_user")
        other_session = ChatSession.objects.create(user=other_user)
        response = self.client.post(
            self.MESSAGE_URL,
            data={"message": "Hello", "session_id": other_session.pk},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_message_requires_authentication(self):
        self.client.force_authenticate(user=None)
        response = self.client.post(
            self.MESSAGE_URL,
            data={"message": "Hello"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def tearDown(self):
        ChatSession.objects.filter(user=self.user).delete()
