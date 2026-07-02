# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from django.test import TestCase, override_settings
from django.utils.timezone import now
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.errors import GraphRecursionError

from api_app.chatbot_manager import events
from api_app.chatbot_manager.models import ChatMessage, ChatSession
from api_app.chatbot_manager.tasks import delete_old_chat_sessions, process_chat_message
from certego_saas.apps.user.models import User

INMEMORY_CHANNEL_LAYER = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}


class _FakeRunnable:
    """Stand-in for the compiled agent: replays scripted (mode, payload) tuples from .stream and
    records the call, so the task's inputs/config hand-off contract can be asserted."""

    def __init__(self, items=(), raises=None):
        self._items = items
        self._raises = raises
        self.stream_calls = []

    def stream(self, inputs, stream_mode=None, config=None):
        self.stream_calls.append(SimpleNamespace(inputs=inputs, stream_mode=stream_mode, config=config))
        if self._raises is not None:
            raise self._raises
        yield from self._items


def _chat_agent(items=(), raises=None):
    runnable = _FakeRunnable(items=items, raises=raises)
    return SimpleNamespace(runnable=runnable, tool_names=frozenset()), runnable


def _final(text):
    return [("values", {"messages": [AIMessage(content=text)]})]


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
        self.assertFalse(ChatMessage.objects.filter(pk__in=message_pks).exists())

    def test_keeps_recent_session(self):
        session = self._session_with_last_message(days_old=5)
        self.assertEqual(delete_old_chat_sessions(), 0)
        self.assertTrue(ChatSession.objects.filter(pk=session.pk).exists())

    def test_boundary_around_cutoff(self):
        stale = self._session_with_last_message(days_old=31)
        fresh = self._session_with_last_message(days_old=29)
        self.assertEqual(delete_old_chat_sessions(), 1)
        self.assertFalse(ChatSession.objects.filter(pk=stale.pk).exists())
        self.assertTrue(ChatSession.objects.filter(pk=fresh.pk).exists())

    def test_empty_session_uses_created_at(self):
        old_empty = ChatSession.objects.create(user=self.user, created_at=now() - datetime.timedelta(days=40))
        recent_empty = ChatSession.objects.create(
            user=self.user, created_at=now() - datetime.timedelta(days=5)
        )
        self.assertEqual(delete_old_chat_sessions(), 1)
        self.assertFalse(ChatSession.objects.filter(pk=old_empty.pk).exists())
        self.assertTrue(ChatSession.objects.filter(pk=recent_empty.pk).exists())

    def test_old_session_with_recent_message_is_kept(self):
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

    The agent is mocked, so the LLM/Ollama is never touched; token/status/action events come from
    the stream consumer (covered in test_streaming) and are not exercised here.
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
        return [call.args[1]["payload"]["type"] for call in layer.group_send.call_args_list]

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent")
    def test_persists_turn_and_streams_start_end(self, mock_build, mock_get_layer):
        layer = self._patched_layer(mock_get_layer)
        chat_agent, runnable = _chat_agent(items=_final("Hi there"))
        mock_build.return_value = chat_agent

        process_chat_message(self.session.id, "hello", self.user.id)

        messages = list(
            ChatMessage.objects.filter(session=self.session)
            .order_by("timestamp")
            .values_list("role", "content")
        )
        self.assertEqual(
            messages, [(ChatMessage.Role.USER, "hello"), (ChatMessage.Role.ASSISTANT, "Hi there")]
        )
        self.assertEqual(
            self._event_types(layer), [events.ChatEventType.START.value, events.ChatEventType.END.value]
        )

        end_payload = layer.group_send.call_args_list[-1].args[1]["payload"]
        assistant = ChatMessage.objects.get(session=self.session, role=ChatMessage.Role.ASSISTANT)
        self.assertEqual(end_payload["message_id"], assistant.id)
        self.assertEqual(end_payload["content"], "Hi there")

        # the run streams both modes with the recursion bound in config
        from api_app.chatbot_manager.agent.agent import RECURSION_LIMIT

        call = runnable.stream_calls[0]
        self.assertEqual(call.stream_mode, ["messages", "values"])
        self.assertEqual(call.config, {"recursion_limit": RECURSION_LIMIT})

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent")
    def test_prior_turns_reach_the_agent_as_messages(self, mock_build, mock_get_layer):
        self._patched_layer(mock_get_layer)
        ChatMessage.objects.create(session=self.session, role=ChatMessage.Role.USER, content="prev q")
        ChatMessage.objects.create(session=self.session, role=ChatMessage.Role.ASSISTANT, content="prev a")
        chat_agent, runnable = _chat_agent(items=_final("ok"))
        mock_build.return_value = chat_agent

        process_chat_message(self.session.id, "hello", self.user.id)

        # history + the new user message feed the agent as LangChain message objects, snapshotted
        # before this turn is persisted so the current message is not double-counted.
        sent_messages = runnable.stream_calls[0].inputs["messages"]
        self.assertEqual(
            [(type(m), m.content) for m in sent_messages],
            [(HumanMessage, "prev q"), (AIMessage, "prev a"), (HumanMessage, "hello")],
        )

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent")
    def test_agent_failure_streams_error_and_drops_the_turn(self, mock_build, mock_get_layer):
        layer = self._patched_layer(mock_get_layer)
        chat_agent, _ = _chat_agent(raises=ConnectionError("ollama down"))
        mock_build.return_value = chat_agent

        process_chat_message(self.session.id, "hello", self.user.id)

        self.assertFalse(ChatMessage.objects.filter(session=self.session).exists())
        self.assertEqual(
            self._event_types(layer), [events.ChatEventType.START.value, events.ChatEventType.ERROR.value]
        )
        error_payload = layer.group_send.call_args_list[-1].args[1]["payload"]
        self.assertEqual(error_payload["detail"], events.ChatErrorDetail.UNAVAILABLE.value)

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent")
    def test_recursion_cap_streams_error_and_drops_the_turn(self, mock_build, mock_get_layer):
        layer = self._patched_layer(mock_get_layer)
        chat_agent, _ = _chat_agent(raises=GraphRecursionError("recursion limit reached"))
        mock_build.return_value = chat_agent

        process_chat_message(self.session.id, "hello", self.user.id)

        # a looping run is dropped, not persisted
        self.assertFalse(ChatMessage.objects.filter(session=self.session).exists())
        self.assertEqual(
            self._event_types(layer), [events.ChatEventType.START.value, events.ChatEventType.ERROR.value]
        )
        error_payload = layer.group_send.call_args_list[-1].args[1]["payload"]
        self.assertEqual(error_payload["detail"], events.ChatErrorDetail.ITERATION_LIMIT.value)

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent")
    def test_context_url_is_injected_as_page_context(self, mock_build, mock_get_layer):
        self._patched_layer(mock_get_layer)
        chat_agent, _ = _chat_agent(items=_final("ok"))
        mock_build.return_value = chat_agent

        process_chat_message(self.session.id, "summarize this", self.user.id, "https://intelowl.test/jobs/42")

        self.assertEqual(
            mock_build.call_args.kwargs["page_context"],
            "The user is currently viewing job #42 in the IntelOwl UI.",
        )

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent")
    def test_missing_context_url_yields_empty_page_context(self, mock_build, mock_get_layer):
        self._patched_layer(mock_get_layer)
        chat_agent, _ = _chat_agent(items=_final("ok"))
        mock_build.return_value = chat_agent

        process_chat_message(self.session.id, "hello", self.user.id)  # no context_url

        self.assertEqual(mock_build.call_args.kwargs["page_context"], "")

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent")
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
