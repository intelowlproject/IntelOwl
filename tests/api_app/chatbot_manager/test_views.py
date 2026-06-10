# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.utils.timezone import now
from langchain_core.messages import AIMessage, HumanMessage
from rest_framework import status
from rest_framework.test import APITestCase

from api_app.chatbot_manager.agent.agent import AGENT_STOPPED_OUTPUT
from api_app.chatbot_manager.events import ChatErrorDetail
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

    @patch("api_app.chatbot_manager.views.build_agent_executor")
    def test_message_passes_prior_turns_as_messages(self, mock_build):
        executor = MagicMock()
        executor.invoke.return_value = MOCK_AGENT_OUTPUT
        mock_build.return_value = executor
        session = ChatSession.objects.create(user=self.user)
        ChatMessage.objects.create(session=session, role=ChatMessage.Role.USER, content="prev q")
        ChatMessage.objects.create(session=session, role=ChatMessage.Role.ASSISTANT, content="prev a")

        response = self.client.post(
            self.MESSAGE_URL,
            data={"message": "Hello", "session_id": session.pk},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # history reaches the agent as LangChain message objects (the prompt's chat_history
        # MessagesPlaceholder), read before this turn is persisted.
        invoke_input = executor.invoke.call_args.args[0]
        self.assertEqual(invoke_input["input"], "Hello")
        self.assertEqual(
            [(type(m), m.content) for m in invoke_input["chat_history"]],
            [(HumanMessage, "prev q"), (AIMessage, "prev a")],
        )

    @patch("api_app.chatbot_manager.views.build_agent_executor")
    def test_message_iteration_cap_returns_error_and_drops_the_turn(self, mock_build):
        executor = MagicMock()
        # what AgentExecutor returns when max_iterations force-stops the run
        executor.invoke.return_value = {"output": AGENT_STOPPED_OUTPUT}
        mock_build.return_value = executor
        session = ChatSession.objects.create(user=self.user)

        response = self.client.post(
            self.MESSAGE_URL,
            data={"message": "Hello", "session_id": session.pk},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        content = response.json()
        self.assertEqual(content["detail"], ChatErrorDetail.ITERATION_LIMIT.value)
        # the session id rides the error so a session created by this request stays usable
        self.assertEqual(content["session_id"], session.pk)
        # the canned framework string must never be persisted as an assistant message
        self.assertFalse(ChatMessage.objects.filter(session=session).exists())

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


class ChatSessionMessagesActionTestCase(APITestCase):
    """Tests for GET /api/chatbot/sessions/{id}/messages."""

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chatbot_messages_user")
        self.client.force_authenticate(user=self.user)
        self.session = ChatSession.objects.create(user=self.user)

    @staticmethod
    def _url(pk):
        return f"/api/chatbot/sessions/{pk}/messages"

    def test_returns_messages_ordered_by_timestamp(self):
        # Persist in reverse chronological order to prove the endpoint sorts by
        # timestamp ascending rather than echoing insertion order.
        base = now()
        ChatMessage.objects.create(
            session=self.session,
            role=ChatMessage.Role.ASSISTANT,
            content="second",
            timestamp=base + timedelta(seconds=2),
        )
        ChatMessage.objects.create(
            session=self.session,
            role=ChatMessage.Role.USER,
            content="first",
            timestamp=base + timedelta(seconds=1),
        )
        response = self.client.get(self._url(self.session.pk))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.json()["results"]
        self.assertEqual([m["content"] for m in results], ["first", "second"])
        self.assertEqual([m["role"] for m in results], ["user", "assistant"])

    def test_paginated_shape_and_page_size(self):
        base = now()
        for i in range(12):
            ChatMessage.objects.create(
                session=self.session,
                role=ChatMessage.Role.USER,
                content=f"m{i}",
                timestamp=base + timedelta(seconds=i),
            )
        response = self.client.get(self._url(self.session.pk))
        content = response.json()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("count", content)
        self.assertIn("total_pages", content)
        self.assertIn("results", content)
        self.assertEqual(content["count"], 12)
        self.assertEqual(content["total_pages"], 2)
        self.assertEqual(len(content["results"]), 10)  # PAGE_SIZE default

        page2 = self.client.get(self._url(self.session.pk), {"page": 2}).json()
        self.assertEqual(len(page2["results"]), 2)

    def test_empty_session_returns_empty_results(self):
        response = self.client.get(self._url(self.session.pk))
        content = response.json()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(content["count"], 0)
        self.assertEqual(content["results"], [])

    def test_returns_404_for_other_users_session(self):
        other_user, _ = User.objects.get_or_create(username="chatbot_messages_other_user")
        other_session = ChatSession.objects.create(user=other_user)
        response = self.client.get(self._url(other_session.pk))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_requires_authentication(self):
        self.client.force_authenticate(user=None)
        response = self.client.get(self._url(self.session.pk))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def tearDown(self):
        ChatSession.objects.filter(user__username__startswith="chatbot_messages_").delete()
