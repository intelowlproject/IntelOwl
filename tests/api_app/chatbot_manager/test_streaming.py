# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
from unittest.mock import AsyncMock, MagicMock

from django.test import SimpleTestCase
from langchain_core.messages import AIMessage, AIMessageChunk, ToolMessage

from api_app.chatbot_manager import events
from api_app.chatbot_manager.agent.streaming import ChatStreamConsumer

USER_ID = 7
SESSION_ID = 3


def _ai_text(content, msg_id="m1"):
    return AIMessageChunk(content=content, id=msg_id)


def _ai_tool_call(name, msg_id="m1", index=0, args=""):
    return AIMessageChunk(
        content="",
        id=msg_id,
        tool_call_chunks=[
            {"name": name, "args": args, "id": "c1", "index": index, "type": "tool_call_chunk"}
        ],
    )


class _FakeRunnable:
    """Replays a scripted list of (mode, payload) tuples as create_agent's dual-mode stream."""

    def __init__(self, items):
        self._items = items

    def stream(self, inputs, stream_mode=None, config=None):
        assert stream_mode == ["messages", "values"]
        yield from self._items


def _messages_payload(*chunks):
    return [("messages", (chunk, {"langgraph_node": "model"})) for chunk in chunks]


def _values_payload(final_text):
    return ("values", {"messages": [AIMessage(content=final_text)]})


class ChatStreamConsumerTestCase(SimpleTestCase):
    """The consumer streams answer text, one status per tool call, and the guardrail action."""

    @staticmethod
    def _make_consumer(tool_names=None):
        consumer = ChatStreamConsumer(user_id=USER_ID, session_id=SESSION_ID, tool_names=tool_names)
        layer = MagicMock()
        layer.group_send = AsyncMock()
        consumer._channel_layer = layer
        return consumer, layer

    @staticmethod
    def _sent(layer):
        return [call.args for call in layer.group_send.call_args_list]

    def test_text_tokens_stream_in_order(self):
        consumer, layer = self._make_consumer()
        consumer.run(_FakeRunnable(_messages_payload(_ai_text("Hello"), _ai_text(" world"))), {}, {})

        group = events.chat_group_for_user(USER_ID)
        self.assertEqual(
            self._sent(layer),
            [
                (group, events.TokenEvent(SESSION_ID, "Hello").as_channel_message()),
                (group, events.TokenEvent(SESSION_ID, " world").as_channel_message()),
            ],
        )

    def test_empty_text_chunks_are_not_streamed(self):
        # A tool-call delta carries empty text (the call rides tool_call_chunks); nothing hits the
        # wire for its text.
        consumer, layer = self._make_consumer()
        consumer.run(_FakeRunnable(_messages_payload(_ai_text(""), _ai_text(""))), {}, {})
        layer.group_send.assert_not_called()

    def test_mixed_stream_forwards_only_text(self):
        consumer, layer = self._make_consumer()
        consumer.run(
            _FakeRunnable(_messages_payload(_ai_text(""), _ai_text("The"), _ai_text(" answer"))), {}, {}
        )
        contents = [m[1]["payload"]["content"] for m in self._sent(layer)]
        self.assertEqual(contents, ["The", " answer"])

    def test_tool_call_emits_one_status_with_the_tool_name(self):
        consumer, layer = self._make_consumer()
        consumer.run(_FakeRunnable(_messages_payload(_ai_tool_call("search_jobs"))), {}, {})
        self.assertEqual(
            self._sent(layer)[0],
            (
                events.chat_group_for_user(USER_ID),
                events.StatusEvent(SESSION_ID, "search_jobs").as_channel_message(),
            ),
        )

    def test_status_is_deduped_per_tool_call(self):
        # The same tool call streams across several chunks (same message id + index, name only in
        # the first); exactly one chat.status must be emitted for it.
        consumer, layer = self._make_consumer()
        first = _ai_tool_call("search_jobs", msg_id="m1", index=0)
        cont = AIMessageChunk(
            content="",
            id="m1",
            tool_call_chunks=[
                {"name": None, "args": '{"limit":5}', "id": "c1", "index": 0, "type": "tool_call_chunk"}
            ],
        )
        consumer.run(_FakeRunnable(_messages_payload(first, cont)), {}, {})
        statuses = [
            m for m in self._sent(layer) if m[1]["payload"]["type"] == events.ChatEventType.STATUS.value
        ]
        self.assertEqual(len(statuses), 1)

    def test_sequential_tool_rounds_each_emit_a_status(self):
        # Two separate tool calls (distinct message ids) -> two statuses, not deduped together.
        consumer, layer = self._make_consumer()
        consumer.run(
            _FakeRunnable(
                _messages_payload(
                    _ai_tool_call("search_jobs", msg_id="m1"), _ai_tool_call("summarize_job", msg_id="m2")
                )
            ),
            {},
            {},
        )
        tools = [
            m[1]["payload"]["tool"]
            for m in self._sent(layer)
            if m[1]["payload"]["type"] == events.ChatEventType.STATUS.value
        ]
        self.assertEqual(tools, ["search_jobs", "summarize_job"])

    def test_unregistered_tool_status_is_suppressed(self):
        # With a real registry, only registered tool names may surface as chat.status.
        consumer, layer = self._make_consumer(tool_names={"search_jobs"})
        consumer.run(
            _FakeRunnable(
                _messages_payload(
                    _ai_tool_call("_Exception", msg_id="m1"), _ai_tool_call("search_jobs", msg_id="m2")
                )
            ),
            {},
            {},
        )
        tools = [
            m[1]["payload"]["tool"]
            for m in self._sent(layer)
            if m[1]["payload"]["type"] == events.ChatEventType.STATUS.value
        ]
        self.assertEqual(tools, ["search_jobs"])

    def test_tool_output_with_pending_id_emits_action_required(self):
        consumer, layer = self._make_consumer()
        tool_msg = ToolMessage(
            content=json.dumps({"errors": [], "plan": {"observable_name": "x"}, "pending_id": "abc"}),
            name="analyze_observable",
            tool_call_id="c1",
        )
        consumer.run(_FakeRunnable([("messages", (tool_msg, {}))]), {}, {})
        actions = [
            m
            for m in self._sent(layer)
            if m[1]["payload"]["type"] == events.ChatEventType.ACTION_REQUIRED.value
        ]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0][1]["payload"]["pending_id"], "abc")

    def test_plain_tool_output_emits_nothing(self):
        consumer, layer = self._make_consumer()
        tool_msg = ToolMessage(
            content=json.dumps({"errors": [], "jobs": []}), name="search_jobs", tool_call_id="c1"
        )
        consumer.run(_FakeRunnable([("messages", (tool_msg, {}))]), {}, {})
        layer.group_send.assert_not_called()

    def test_run_returns_the_terminal_answer_from_values(self):
        consumer, _ = self._make_consumer()
        items = _messages_payload(_ai_text("Prepared ")) + [
            _values_payload("Prepared the plan. Click Confirm.")
        ]
        answer = consumer.run(_FakeRunnable(items), {}, {})
        self.assertEqual(answer, "Prepared the plan. Click Confirm.")
