# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
from unittest.mock import AsyncMock, MagicMock, patch

from django.test import TestCase

from api_app.chatbot.agent import MAX_TOOL_ROUNDS, run_agent


def _make_chunk(content=None, tool_calls=None, finish_reason=None):
    """Build a mock streaming chunk matching litellm's response format."""
    delta = MagicMock()
    delta.content = content
    delta.tool_calls = tool_calls

    choice = MagicMock()
    choice.delta = delta
    choice.finish_reason = finish_reason

    chunk = MagicMock()
    chunk.choices = [choice]
    return chunk


def _make_tool_call_delta(index=0, tc_id=None, name=None, arguments=None):
    """Build a mock tool_call delta fragment."""
    tc = MagicMock()
    tc.index = index
    tc.id = tc_id
    tc.function = MagicMock()
    tc.function.name = name
    tc.function.arguments = arguments
    return tc


async def _collect_events(async_gen):
    """Collect all events from an async generator into a list."""
    events = []
    async for event in async_gen:
        events.append(event)
    return events


class TestRunAgent(TestCase):
    """Test the core tool-calling loop with mocked litellm."""

    @patch("api_app.chatbot.agent.litellm.acompletion")
    async def test_simple_text_response(self, mock_acompletion):
        """LLM returns text without tool calls."""

        async def mock_stream():
            yield _make_chunk(content="Hello ")
            yield _make_chunk(content="world!")
            yield _make_chunk(finish_reason="stop")

        mock_acompletion.return_value = mock_stream()

        events = await _collect_events(
            run_agent(
                messages=[{"role": "user", "content": "hi"}],
                model="test-model",
            )
        )

        types = [e["type"] for e in events]
        self.assertEqual(types, ["token", "token", "done"])
        self.assertEqual(events[0]["content"], "Hello ")
        self.assertEqual(events[1]["content"], "world!")

    @patch("api_app.chatbot.agent.execute_tool", new_callable=AsyncMock)
    @patch("api_app.chatbot.agent.litellm.acompletion")
    async def test_single_tool_call(self, mock_acompletion, mock_execute):
        """LLM makes a tool call, then responds with text."""
        mock_execute.return_value = {"jobs": [{"id": 1, "status": "completed"}]}

        call_count = 0

        async def mock_stream_factory(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call: LLM requests a tool call.
                async def stream():
                    yield _make_chunk(
                        tool_calls=[
                            _make_tool_call_delta(
                                index=0,
                                tc_id="call_1",
                                name="search_jobs",
                                arguments='{"limit": 5}',
                            )
                        ]
                    )
                    yield _make_chunk(finish_reason="tool_calls")

                return stream()
            else:
                # Second call: LLM responds with text after seeing tool results.
                async def stream():
                    yield _make_chunk(content="Found 1 job.")
                    yield _make_chunk(finish_reason="stop")

                return stream()

        mock_acompletion.side_effect = mock_stream_factory

        events = await _collect_events(
            run_agent(
                messages=[{"role": "user", "content": "show jobs"}],
                model="test-model",
                auth_token="test-token",
            )
        )

        types = [e["type"] for e in events]
        self.assertIn("tool_call", types)
        self.assertIn("tool_result", types)
        self.assertIn("token", types)
        self.assertIn("done", types)
        mock_execute.assert_called_once_with(
            "search_jobs", {"limit": 5}, "test-token"
        )

    @patch("api_app.chatbot.agent.execute_tool", new_callable=AsyncMock)
    @patch("api_app.chatbot.agent.litellm.acompletion")
    async def test_max_rounds_exceeded(self, mock_acompletion, mock_execute):
        """Agent stops after MAX_TOOL_ROUNDS to prevent infinite loops."""
        mock_execute.return_value = {"result": "ok"}

        async def always_tool_call(*args, **kwargs):
            async def stream():
                yield _make_chunk(
                    tool_calls=[
                        _make_tool_call_delta(
                            index=0,
                            tc_id="call_x",
                            name="search_jobs",
                            arguments="{}",
                        )
                    ]
                )
                yield _make_chunk(finish_reason="tool_calls")

            return stream()

        mock_acompletion.side_effect = always_tool_call

        events = await _collect_events(
            run_agent(
                messages=[{"role": "user", "content": "loop"}],
                model="test-model",
                auth_token="test-token",
            )
        )

        error_events = [e for e in events if e["type"] == "error"]
        self.assertEqual(len(error_events), 1)
        self.assertIn("Max tool rounds", error_events[0]["message"])
        self.assertEqual(mock_execute.call_count, MAX_TOOL_ROUNDS)

    @patch("api_app.chatbot.agent.litellm.acompletion")
    async def test_llm_api_error(self, mock_acompletion):
        """Agent yields an error event when the LLM API call fails."""
        mock_acompletion.side_effect = Exception("Connection refused")

        events = await _collect_events(
            run_agent(
                messages=[{"role": "user", "content": "hi"}],
                model="test-model",
            )
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "error")
        self.assertIn("Connection refused", events[0]["message"])
