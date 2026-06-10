# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import AsyncMock, MagicMock

from django.test import SimpleTestCase

from api_app.chatbot_manager import events
from api_app.chatbot_manager.agent.streaming import ChatStreamingCallbackHandler

USER_ID = 7
SESSION_ID = 3


class ChatStreamingCallbackHandlerTestCase(SimpleTestCase):
    """The callback streams answer text and a status per tool action."""

    def _make_handler(self, tool_names=None):
        handler = ChatStreamingCallbackHandler(user_id=USER_ID, session_id=SESSION_ID, tool_names=tool_names)
        layer = MagicMock()
        layer.group_send = AsyncMock()
        handler._channel_layer = layer
        return handler, layer

    @staticmethod
    def _messages(layer):
        # each group_send call is (group, channel_message)
        return [call.args for call in layer.group_send.call_args_list]

    def test_text_tokens_stream_in_order(self):
        handler, layer = self._make_handler()
        for token in ["Hello", " world"]:
            handler.on_llm_new_token(token)

        group = events.chat_group_for_user(USER_ID)
        self.assertEqual(
            self._messages(layer),
            [
                (group, events.TokenEvent(SESSION_ID, "Hello").as_channel_message()),
                (group, events.TokenEvent(SESSION_ID, " world").as_channel_message()),
            ],
        )

    def test_empty_tokens_are_not_streamed(self):
        # A tool-call delta reaches on_llm_new_token with empty text (the call itself rides
        # tool_call_chunks); nothing may hit the wire for it.
        handler, layer = self._make_handler()
        for token in ["", "", ""]:
            handler.on_llm_new_token(token)

        layer.group_send.assert_not_called()

    def test_mixed_stream_forwards_only_text(self):
        # A turn that starts with tool-call deltas and ends with the streamed answer.
        handler, layer = self._make_handler()
        for token in ["", "", "The", " answer"]:
            handler.on_llm_new_token(token)

        contents = [m[1]["payload"]["content"] for m in self._messages(layer)]
        self.assertEqual(contents, ["The", " answer"])

    def test_agent_action_emits_status_event_with_tool_name(self):
        handler, layer = self._make_handler()
        action = MagicMock()
        action.tool = "search_jobs"

        handler.on_agent_action(action)

        self.assertEqual(
            self._messages(layer)[0],
            (
                events.chat_group_for_user(USER_ID),
                events.StatusEvent(SESSION_ID, "search_jobs").as_channel_message(),
            ),
        )

    def test_agent_action_for_unregistered_tool_is_suppressed(self):
        # With a real tool registry, LangChain's "_Exception" parse-error pseudo-tool (and any
        # raw malformed model output as a "tool") must not leak to the client as chat.status.
        handler, layer = self._make_handler(tool_names={"search_jobs"})

        exception_action = MagicMock()
        exception_action.tool = "_Exception"
        handler.on_agent_action(exception_action)
        layer.group_send.assert_not_called()

        real_action = MagicMock()
        real_action.tool = "search_jobs"
        handler.on_agent_action(real_action)
        layer.group_send.assert_called_once()
