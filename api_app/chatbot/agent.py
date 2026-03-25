# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
from typing import AsyncGenerator

import litellm

from .tools import TOOL_SCHEMAS, execute_tool

logger = logging.getLogger(__name__)

MAX_TOOL_ROUNDS = 10


async def run_agent(
    messages: list[dict],
    model: str,
    api_base: str | None = None,
    auth_token: str = "",
) -> AsyncGenerator[dict, None]:
    """Core agent loop. Streams LLM responses and executes tool calls.

    Yields SSE-formatted event dicts:
      {"type": "token", "content": "..."}       — streamed text chunk
      {"type": "tool_call", "name": "...", "args": "..."}  — tool invocation
      {"type": "tool_result", "name": "...", "result": {...}} — tool output
      {"type": "done"}                          — stream complete
      {"type": "error", "message": "..."}       — error occurred
    """
    rounds = 0

    while rounds < MAX_TOOL_ROUNDS:
        rounds += 1
        tool_calls_in_progress = {}
        full_tool_calls = []

        try:
            response = await litellm.acompletion(
                model=model,
                messages=messages,
                tools=TOOL_SCHEMAS,
                tool_choice="auto",
                stream=True,
                api_base=api_base,
            )
        except Exception as e:
            logger.exception("LLM API call failed")
            yield {"type": "error", "message": f"LLM request failed: {e}"}
            return

        async for chunk in response:
            delta = chunk.choices[0].delta

            # Stream text tokens to the client.
            if delta.content:
                yield {"type": "token", "content": delta.content}

            # Accumulate tool calls from streamed chunks.
            if delta.tool_calls:
                for tc in delta.tool_calls:
                    idx = tc.index
                    if idx not in tool_calls_in_progress:
                        tool_calls_in_progress[idx] = {
                            "id": tc.id or "",
                            "name": tc.function.name or "",
                            "arguments": "",
                        }
                    if tc.id:
                        tool_calls_in_progress[idx]["id"] = tc.id
                    if tc.function.name:
                        tool_calls_in_progress[idx]["name"] = tc.function.name
                    if tc.function.arguments:
                        tool_calls_in_progress[idx]["arguments"] += (
                            tc.function.arguments
                        )

            # Check if stream finished.
            finish_reason = chunk.choices[0].finish_reason
            if finish_reason == "stop":
                yield {"type": "done"}
                return

            if finish_reason == "tool_calls":
                full_tool_calls = list(tool_calls_in_progress.values())

        if not full_tool_calls:
            yield {"type": "done"}
            return

        # Append assistant message with tool calls to conversation history.
        messages.append(
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": tc["id"],
                        "type": "function",
                        "function": {
                            "name": tc["name"],
                            "arguments": tc["arguments"],
                        },
                    }
                    for tc in full_tool_calls
                ],
            }
        )

        # Execute each tool call and append results.
        for tc in full_tool_calls:
            yield {"type": "tool_call", "name": tc["name"], "args": tc["arguments"]}

            try:
                args = json.loads(tc["arguments"])
                result = await execute_tool(tc["name"], args, auth_token)
            except Exception as e:
                logger.exception("Tool execution failed: %s", tc["name"])
                result = {"error": str(e)}

            yield {"type": "tool_result", "name": tc["name"], "result": result}

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": json.dumps(result),
                }
            )
        # Loop continues — LLM processes tool results next.

    yield {"type": "error", "message": "Max tool rounds exceeded"}
