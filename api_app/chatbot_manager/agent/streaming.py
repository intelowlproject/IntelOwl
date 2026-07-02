# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Consumes a create_agent run and streams the chat turn to the WebSocket as it happens.

LangChain 1.x exposes streaming through the LangGraph runtime, so instead of a callback handler we
drive the run with ``runnable.stream(stream_mode=["messages", "values"])`` and translate it into the
same wire events:

- ``messages`` yields ``(message_chunk, metadata)``: ``AIMessageChunk`` text becomes ``chat.token``;
  its ``tool_call_chunks`` become one ``chat.status`` per tool call; a ``ToolMessage`` carrying a
  ``pending_id`` becomes ``chat.action_required`` (the M-1 guardrail preview).
- ``values`` yields the full state after each step; the terminal message is the answer persisted and
  sent in ``chat.end`` (the source of truth — the streamed tokens are a best-effort live preview).

Running inside the (synchronous) Celery worker means there is no event loop, so ``async_to_sync`` is
the right bridge to the async channel layer — the same pattern ``JobConsumer`` already uses.
"""

import json
import logging

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from langchain_core.messages import AIMessageChunk, ToolMessage

from api_app.chatbot_manager.agent.agent import final_answer
from api_app.chatbot_manager.events import (
    ActionRequiredEvent,
    ChatEvent,
    StatusEvent,
    TokenEvent,
    chat_group_for_user,
)

logger = logging.getLogger(__name__)


class ChatStreamConsumer:
    """Streams a create_agent run to a user's channel group and returns the final answer.

    With a tool-calling agent there is no ``Final Answer:`` marker: the model streams plain text for
    the answer and rides tool calls on ``tool_call_chunks`` (whose text is empty). Forwarding only
    non-empty text therefore streams the answer while keeping tool-call payloads off the wire. A
    model may emit a short text preamble before a tool call, which streams and is then superseded by
    the real answer; ``chat.end`` carries the terminal message, which the client treats as truth, so
    the stored/displayed answer is always correct.
    """

    def __init__(self, user_id: int, session_id: int, tool_names: frozenset[str] | None = None):
        self._group = chat_group_for_user(user_id)
        self._session_id = session_id
        # Only these tool names produce a chat.status; None means "emit any" (unit tests). Filtering
        # by the real registry keeps any non-registered tool name off the wire as chat.status.
        self._tool_names = tool_names
        self._channel_layer = get_channel_layer()
        # (message_id, tool_call_index) already announced, so a tool call whose name streams across
        # several chunks yields exactly one chat.status while distinct rounds each get their own.
        self._status_seen: set[tuple] = set()

    def _emit(self, event: ChatEvent) -> None:
        async_to_sync(self._channel_layer.group_send)(self._group, event.as_channel_message())

    def run(self, agent_runnable, inputs: dict, config: dict) -> str:
        """Stream the run, emitting token/status/action events, and return the terminal answer."""
        answer = ""
        for mode, payload in agent_runnable.stream(inputs, stream_mode=["messages", "values"], config=config):
            if mode == "messages":
                self._handle_message(payload[0])
            elif mode == "values":
                terminal = final_answer(payload.get("messages") or [])
                if terminal:
                    answer = terminal
        return answer

    def _handle_message(self, message) -> None:
        if isinstance(message, AIMessageChunk):
            # Tool-call deltas surface here with empty text; only real answer text is forwarded.
            if message.text:
                self._emit(TokenEvent(self._session_id, message.text))
            for chunk in message.tool_call_chunks or []:
                self._maybe_status(message.id, chunk)
        elif isinstance(message, ToolMessage):
            self._maybe_action_required(message.content)

    def _maybe_status(self, message_id, tool_call_chunk) -> None:
        name = tool_call_chunk.get("name")
        if not name:
            return
        key = (message_id, tool_call_chunk.get("index"))
        if key in self._status_seen or (self._tool_names is not None and name not in self._tool_names):
            return
        self._status_seen.add(key)
        self._emit(StatusEvent(self._session_id, name))

    def _maybe_action_required(self, content) -> None:
        # analyze_observable returns an envelope carrying a one-time pending_id; surface it as a
        # structured action so the frontend can render a Confirm button. Other tools have no
        # pending_id, so this is a no-op for them.
        try:
            data = json.loads(content)
        except (TypeError, ValueError):
            logger.warning("stream: cannot parse tool output as JSON")
            return
        if isinstance(data, dict) and data.get("pending_id"):
            self._emit(ActionRequiredEvent(self._session_id, data["pending_id"], data.get("plan") or {}))
