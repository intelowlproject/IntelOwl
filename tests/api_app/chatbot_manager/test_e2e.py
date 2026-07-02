# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""End-to-end tests of the chatbot chat pipeline.

These wire the *real* components together — ChatConsumer, the process_chat_message Celery task,
ChatStreamConsumer, the analyze_observable tool, the pending-action store and the
confirm endpoint — and mock only the external boundaries: the LLM (via build_agent) and
the job pipeline (apply_async). Ollama and the network are never touched.

Transport: the consumer leg does NOT use WebsocketCommunicator. A synchronous JsonWebsocketConsumer
keeps a channel-layer receive listener bound to its event loop, and a real InMemoryChannelLayer
round-trip reads an asyncio.Queue bound to the producer's (separate) async_to_sync loop — both are
the loop-binding hang documented in test_consumers.py. Instead _CapturingChannelLayer records the
plain-dict group_send payloads (loop-safe), which are then fed to the consumer's real chat.<type>
relay handlers, exercising every real component bar the framework's queue plumbing.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.core.cache import caches
from django.test import TestCase, override_settings
from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage, ToolMessage
from rest_framework import status
from rest_framework.test import APIClient

from api_app.chatbot_manager import events
from api_app.chatbot_manager.agent.tools import build_tools
from api_app.chatbot_manager.consumers import ChatConsumer
from api_app.chatbot_manager.models import ChatMessage, ChatSession
from api_app.chatbot_manager.tasks import process_chat_message
from api_app.models import Job
from certego_saas.apps.user.models import User

_ASSISTANT_OUTPUT = "Prepared an analysis plan for example.com. Click Confirm to run it."
_APPLY_ASYNC = "intel_owl.tasks.job_pipeline.apply_async"
_CONFIRM_URL = "/api/chatbot/analysis/confirm"

_LOCMEM = "django.core.cache.backends.locmem.LocMemCache"
# Distinct LOCATIONs so the rate-limit and pending-action stores don't share one dict; locmem is
# process-global, so each test clears these in setUp to stop entries bleeding across tests.
LOCMEM_CACHES = {
    "default": {"BACKEND": _LOCMEM, "LOCATION": "e2e-default"},
    "chatbot_rate_limit": {"BACKEND": _LOCMEM, "LOCATION": "e2e-rl"},
    "chatbot_pending_action": {"BACKEND": _LOCMEM, "LOCATION": "e2e-pa"},
}


class _CapturingChannelLayer:
    """Records group_send payloads instead of queueing them (see module docstring for why)."""

    def __init__(self):
        self.sent = []  # ordered list of (group, channel_message)

    async def group_send(self, group, message):
        self.sent.append((group, message))

    async def group_add(self, group, channel):
        pass

    async def group_discard(self, group, channel):
        pass


def _fake_agent(user):
    """A stand-in ChatAgent whose runnable.stream() drives the REAL stream consumer exactly as a
    tool-calling turn would: a tool-call chunk (chat.status), the real analyze_observable tool output
    as a ToolMessage (chat.action_required, carrying a real one-time pending_id), a streamed answer
    token (chat.token), then the terminal state (persisted answer). Keeps the consumer, the tool and
    the pending-action store real while Ollama is never reached."""
    real_tools = build_tools(user=user)
    # dict lookup (not next()) so a missing tool fails loudly with a KeyError naming it
    analyze_tool = {tool.name: tool for tool in real_tools}["analyze_observable"]

    class _FakeRunnable:
        @staticmethod
        def stream(inputs, stream_mode=None, config=None):
            # tool decision -> chat.status (tool_call_chunks carry the name)
            yield (
                "messages",
                (
                    AIMessageChunk(
                        content="",
                        id="m1",
                        tool_call_chunks=[
                            {
                                "name": "analyze_observable",
                                "args": "",
                                "id": "c1",
                                "index": 0,
                                "type": "tool_call_chunk",
                            }
                        ],
                    ),
                    {"langgraph_node": "model"},
                ),
            )
            # Real tool run: validates the observable and mints a real pending_id in the cache.
            tool_output = analyze_tool.invoke({"observable_name": "example.com", "analyzers": "Tranco"})
            yield (
                "messages",
                (ToolMessage(content=tool_output, name="analyze_observable", tool_call_id="c1"), {}),
            )
            # streamed answer token -> chat.token
            yield ("messages", (AIMessageChunk(content="Prepared the analysis plan. ", id="m2"), {}))
            # terminal state -> the persisted answer sent in chat.end
            yield (
                "values",
                {
                    "messages": [
                        HumanMessage(content="analyze example.com"),
                        AIMessage(content=_ASSISTANT_OUTPUT),
                    ]
                },
            )

    # The task derives the chat.status filter from this real registry, so it is exercised against
    # real tool names.
    return SimpleNamespace(runnable=_FakeRunnable(), tool_names=frozenset(tool.name for tool in real_tools))


def _connected_consumer(user, channel_layer):
    """A ChatConsumer wired for direct calls with the capturing layer; real connect() sets up the
    per-user group name. accept/send_json are mocked so the relayed client frames can be captured."""
    consumer = ChatConsumer()
    consumer.scope = {"user": user, "query_string": b"", "url_route": {"kwargs": {}}}
    consumer.channel_name = "test.chat"
    consumer.channel_layer = channel_layer
    consumer.accept = MagicMock()
    consumer.send_json = MagicMock()
    consumer.connect()  # sets group_name = chat-<user_id>; group_add is a no-op on the capturing layer
    return consumer


@override_settings(
    CACHES=LOCMEM_CACHES,
    CHATBOT_PENDING_ACTION_TTL=600,
    CHATBOT_RATE_LIMIT=1000,
    CHATBOT_RATE_LIMIT_WINDOW=60,
)
class ChatPipelineE2ETestCase(TestCase):
    """The full WebSocket turn: consumer -> task -> agent -> streaming callback -> relayed frames."""

    def setUp(self):
        for alias in ("default", "chatbot_rate_limit", "chatbot_pending_action"):
            caches[alias].clear()
        self.user, _ = User.objects.get_or_create(username="e2e_chat_user")

    def tearDown(self):
        Job.objects.filter(user=self.user).delete()

    def _run_turn(self, *, message="analyze example.com", session_id=None):
        """Run one turn end-to-end and return (consumer, layer, ack_frames, relay_frames).

        ack_frames are what receive_json sent back synchronously (the ack). relay_frames are the
        client payloads produced by replaying each captured group_send through the consumer's real
        chat.<type> handler — i.e. exactly what the browser would receive.
        """
        layer = _CapturingChannelLayer()
        consumer = _connected_consumer(self.user, layer)
        with (
            patch(
                "api_app.chatbot_manager.agent.agent.build_agent",
                return_value=_fake_agent(self.user),
            ),
            patch("api_app.chatbot_manager.tasks.get_channel_layer", return_value=layer),
            patch("api_app.chatbot_manager.agent.streaming.get_channel_layer", return_value=layer),
            patch("api_app.chatbot_manager.consumers.process_chat_message") as consumer_task,
        ):
            # The consumer enqueues via .delay; forward to the real task body so the hand-off
            # contract (exact args) is exercised and the turn runs synchronously in-test. The task
            # object is itself callable, so it is the side_effect directly (no wrapping lambda).
            consumer_task.delay.side_effect = process_chat_message
            content = {"message": message}
            if session_id is not None:
                content["session_id"] = session_id
            consumer.receive_json(content)

        ack_frames = [call.args[0] for call in consumer.send_json.call_args_list]
        consumer.send_json.reset_mock()
        # Replay each captured group message through the framework's type->method mapping.
        for _group, channel_message in layer.sent:
            getattr(consumer, channel_message["type"].replace(".", "_"))(channel_message)
        relay_frames = [call.args[0] for call in consumer.send_json.call_args_list]
        return consumer, layer, ack_frames, relay_frames

    def test_full_turn_streams_tool_call_and_guardrail(self):
        consumer, layer, ack_frames, relay_frames = self._run_turn()
        session = ChatSession.objects.get(user=self.user)

        # ack first, carrying the resolved (newly created) session id
        self.assertEqual(ack_frames, [events.AckEvent(session.id).to_client()])

        # every producer send targeted this user's group (the consumer's own subscription)
        self.assertTrue(layer.sent)
        self.assertTrue(all(group == consumer.group_name for group, _ in layer.sent))

        # ordered client frames for a tool-calling turn with an M-1 preview
        self.assertEqual(
            [frame["type"] for frame in relay_frames],
            [
                events.ChatEventType.START.value,
                events.ChatEventType.STATUS.value,
                events.ChatEventType.ACTION_REQUIRED.value,
                events.ChatEventType.TOKEN.value,
                events.ChatEventType.END.value,
            ],
        )

        # every frame is stamped with the session id (the client's demux key)
        self.assertTrue(all(frame["session_id"] == session.id for frame in relay_frames))

        # status names the real tool; action_required carries a pending id + a plan
        self.assertEqual(relay_frames[1]["tool"], "analyze_observable")
        action = relay_frames[2]
        self.assertTrue(action["pending_id"])
        self.assertEqual(action["plan"]["observable_name"], "example.com")
        self.assertEqual(action["plan"]["classification"], "domain")

        # end carries the persisted assistant message + its id
        assistant = ChatMessage.objects.get(session=session, role=ChatMessage.Role.ASSISTANT)
        self.assertEqual(relay_frames[-1]["message_id"], assistant.id)
        self.assertEqual(relay_frames[-1]["content"], _ASSISTANT_OUTPUT)

        # the exchange is persisted user-then-assistant
        self.assertEqual(
            list(
                ChatMessage.objects.filter(session=session)
                .order_by("timestamp")
                .values_list("role", "content")
            ),
            [(ChatMessage.Role.USER, "analyze example.com"), (ChatMessage.Role.ASSISTANT, _ASSISTANT_OUTPUT)],
        )

    def test_action_required_pending_id_confirms_and_launches_once(self):
        # The pending_id surfaced to the browser in action_required is the only thing needed to
        # launch: a real user POST of it to the confirm endpoint starts the job (M-1 — the model
        # itself never launches).
        _consumer, _layer, _ack, relay_frames = self._run_turn()
        # exactly one action_required frame is expected; index it (not next()) so an empty/oversized
        # match fails loudly here rather than with a bare StopIteration
        action_frames = [
            frame for frame in relay_frames if frame["type"] == events.ChatEventType.ACTION_REQUIRED.value
        ]
        self.assertEqual(len(action_frames), 1)
        pending_id = action_frames[0]["pending_id"]

        client = APIClient()
        client.force_authenticate(self.user)
        with patch(_APPLY_ASYNC) as mock_apply:
            first = client.post(_CONFIRM_URL, {"pending_id": pending_id}, format="json")
            self.assertEqual(first.status_code, status.HTTP_200_OK)
            self.assertEqual(first.json()["errors"], [])
            job_id = first.json()["job"]["id"]
            # multi-tenancy: the launched job is owned by the confirming user
            self.assertEqual(Job.objects.get(pk=job_id).user, self.user)

            # one-shot: the consumed pending id cannot launch a second job
            second = client.post(_CONFIRM_URL, {"pending_id": pending_id}, format="json")
            self.assertEqual(second.status_code, status.HTTP_410_GONE)
            mock_apply.assert_called_once()

    def test_frames_are_tagged_per_session_for_multi_tab_demux(self):
        # Frames fan out to every tab of a user (one per-user group); a tab demultiplexes by the
        # session_id each frame carries. Two sessions of the same user must produce disjoint tags so
        # a tab pinned to one session drops the other's frames.
        session_a = ChatSession.objects.create(user=self.user)
        session_b = ChatSession.objects.create(user=self.user)

        _ca, _la, _acka, frames_a = self._run_turn(session_id=session_a.id)
        _cb, _lb, _ackb, frames_b = self._run_turn(session_id=session_b.id)

        self.assertNotEqual(session_a.id, session_b.id)
        self.assertTrue(frames_a and all(frame["session_id"] == session_a.id for frame in frames_a))
        self.assertTrue(frames_b and all(frame["session_id"] == session_b.id for frame in frames_b))
        # session A's stream contains nothing a tab on session B would accept
        self.assertFalse(any(frame["session_id"] == session_b.id for frame in frames_a))
