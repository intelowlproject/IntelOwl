# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from django.test import TestCase, override_settings
from django.utils.timezone import now
from langchain_core.messages import AIMessage, HumanMessage

from api_app.chatbot_manager import events
from api_app.chatbot_manager.agent.agent import AGENT_STOPPED_OUTPUT
from api_app.chatbot_manager.models import ChatMessage, ChatSession
from api_app.chatbot_manager.tasks import delete_old_chat_sessions, process_chat_message
from certego_saas.apps.user.models import User

INMEMORY_CHANNEL_LAYER = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}


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


@override_settings(CHANNEL_LAYERS=INMEMORY_CHANNEL_LAYER)
class ProcessChatMessageTestCase(TestCase):
    """The Celery turn persists the exchange, streams start/end, and fails closed.

    The agent executor is mocked, so the LLM/Ollama is never touched; the token/status events
    come from the agent's own callbacks (covered in test_streaming) and are not exercised here.
    """

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chatbot_task_user")
        self.session = ChatSession.objects.create(user=self.user)

    @staticmethod
    def _patched_layer(mock_get_layer):
        layer = MagicMock()
        layer.group_send = AsyncMock()
        mock_get_layer.return_value = layer
        return layer

    @staticmethod
    def _event_types(layer):
        # client-facing payload type of each group_send (start/status/token/end/error)
        return [call.args[1]["payload"]["type"] for call in layer.group_send.call_args_list]

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent_executor")
    def test_persists_turn_and_streams_start_end(self, mock_build, mock_get_layer):
        layer = self._patched_layer(mock_get_layer)
        executor = MagicMock()
        executor.invoke.return_value = {"output": "Hi there"}
        mock_build.return_value = executor

        process_chat_message(self.session.id, "hello", self.user.id)

        messages = list(
            ChatMessage.objects.filter(session=self.session)
            .order_by("timestamp")
            .values_list("role", "content")
        )
        self.assertEqual(
            messages,
            [(ChatMessage.Role.USER, "hello"), (ChatMessage.Role.ASSISTANT, "Hi there")],
        )
        self.assertEqual(
            self._event_types(layer),
            [events.ChatEventType.START.value, events.ChatEventType.END.value],
        )

        end_payload = layer.group_send.call_args_list[-1].args[1]["payload"]
        assistant = ChatMessage.objects.get(session=self.session, role=ChatMessage.Role.ASSISTANT)
        self.assertEqual(end_payload["message_id"], assistant.id)
        self.assertEqual(end_payload["content"], "Hi there")

        # streaming requested on the model + callbacks attached at run level (not on the LLM)
        self.assertTrue(mock_build.call_args.kwargs["streaming"])
        self.assertIn("callbacks", executor.invoke.call_args.kwargs["config"])

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent_executor")
    def test_prior_turns_reach_the_agent_as_messages(self, mock_build, mock_get_layer):
        self._patched_layer(mock_get_layer)
        ChatMessage.objects.create(session=self.session, role=ChatMessage.Role.USER, content="prev q")
        ChatMessage.objects.create(session=self.session, role=ChatMessage.Role.ASSISTANT, content="prev a")
        executor = MagicMock()
        executor.invoke.return_value = {"output": "ok"}
        mock_build.return_value = executor

        process_chat_message(self.session.id, "hello", self.user.id)

        # history feeds the prompt's chat_history MessagesPlaceholder directly: LangChain
        # message objects (not pre-rendered text), snapshotted before this turn is persisted
        # so the current message is not part of it.
        invoke_input = executor.invoke.call_args.args[0]
        self.assertEqual(invoke_input["input"], "hello")
        self.assertEqual(
            [(type(m), m.content) for m in invoke_input["chat_history"]],
            [(HumanMessage, "prev q"), (AIMessage, "prev a")],
        )

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent_executor")
    def test_agent_failure_streams_error_and_drops_the_turn(self, mock_build, mock_get_layer):
        layer = self._patched_layer(mock_get_layer)
        executor = MagicMock()
        executor.invoke.side_effect = ConnectionError("ollama down")
        mock_build.return_value = executor

        process_chat_message(self.session.id, "hello", self.user.id)

        # failed turn is dropped: neither the user nor the assistant message is stored
        self.assertFalse(ChatMessage.objects.filter(session=self.session).exists())
        self.assertEqual(
            self._event_types(layer),
            [events.ChatEventType.START.value, events.ChatEventType.ERROR.value],
        )
        error_payload = layer.group_send.call_args_list[-1].args[1]["payload"]
        self.assertEqual(error_payload["detail"], events.ChatErrorDetail.UNAVAILABLE.value)

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent_executor")
    def test_iteration_cap_streams_error_and_drops_the_turn(self, mock_build, mock_get_layer):
        layer = self._patched_layer(mock_get_layer)
        executor = MagicMock()
        # what AgentExecutor returns when max_iterations force-stops the run
        executor.invoke.return_value = {"output": AGENT_STOPPED_OUTPUT}
        mock_build.return_value = executor

        process_chat_message(self.session.id, "hello", self.user.id)

        # the canned framework string must never be persisted as an assistant message
        self.assertFalse(ChatMessage.objects.filter(session=self.session).exists())
        self.assertEqual(
            self._event_types(layer),
            [events.ChatEventType.START.value, events.ChatEventType.ERROR.value],
        )
        error_payload = layer.group_send.call_args_list[-1].args[1]["payload"]
        self.assertEqual(error_payload["detail"], events.ChatErrorDetail.ITERATION_LIMIT.value)

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent_executor")
    def test_context_url_is_injected_as_page_context(self, mock_build, mock_get_layer):
        self._patched_layer(mock_get_layer)
        executor = MagicMock()
        executor.invoke.return_value = {"output": "ok"}
        mock_build.return_value = executor

        process_chat_message(self.session.id, "summarize this", self.user.id, "https://intelowl.test/jobs/42")

        invoke_input = executor.invoke.call_args.args[0]
        self.assertEqual(
            invoke_input["page_context"],
            "The user is currently viewing job #42 in the IntelOwl UI.",
        )

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent_executor")
    def test_missing_context_url_yields_empty_page_context(self, mock_build, mock_get_layer):
        self._patched_layer(mock_get_layer)
        executor = MagicMock()
        executor.invoke.return_value = {"output": "ok"}
        mock_build.return_value = executor

        process_chat_message(self.session.id, "hello", self.user.id)  # no context_url

        self.assertEqual(executor.invoke.call_args.args[0]["page_context"], "")

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent_executor")
    def test_session_not_owned_by_user_is_rejected(self, mock_build, mock_get_layer):
        layer = self._patched_layer(mock_get_layer)
        other = User.objects.create(username="chatbot_task_other")
        foreign_session = ChatSession.objects.create(user=other)

        process_chat_message(foreign_session.id, "hello", self.user.id)

        mock_build.assert_not_called()
        self.assertFalse(ChatMessage.objects.filter(session=foreign_session).exists())
        self.assertEqual(self._event_types(layer), [events.ChatEventType.ERROR.value])
        error_payload = layer.group_send.call_args_list[0].args[1]["payload"]
        self.assertEqual(error_payload["detail"], events.ChatErrorDetail.SESSION_NOT_FOUND.value)
