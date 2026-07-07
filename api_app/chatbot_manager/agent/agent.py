# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from dataclasses import dataclass
from pathlib import Path

from django.conf import settings
from langchain.agents import create_agent
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.runnables import Runnable
from langchain_ollama import ChatOllama

from .tools import build_tools

# The system prompt lives in its own text file so it is readable, testable, and editable without
# touching Python code. The page context (if any) is appended by build_agent at build time so the
# file stays self-contained (no interpolation).
_SYSTEM_PROMPT = Path(__file__).parent.joinpath("system_prompt.txt").read_text(encoding="utf-8").strip()

# One "round" = one model turn that calls a tool + its observation. Real questions resolve in 1-3
# rounds (analyze_observable's confirm flow spans two turns, not two rounds), so 6 leaves room for
# a retry after a failed call while force-stopping a looping model well before the Celery task's
# 300s soft time limit would on CPU.
_MAX_AGENT_ITERATIONS = 6

# LangGraph bounds a run by supersteps (its recursion_limit), not by agent rounds, and the count is
# not 1:1 with rounds: one tool round is model -> tools -> model (2 supersteps), the run then ends
# with a terminal model reply (+1), and LangGraph raises when the *next* superstep would reach the
# limit (a boundary +1). So N rounds needs 2*N + 2 (measured: a single tool round completes only at
# recursion_limit >= 4). This preserves the old max_iterations=6 force-stop budget under the new
# runtime; a run that keeps calling tools raises GraphRecursionError, which the callers map to
# ChatErrorDetail.ITERATION_LIMIT (there is no canned "stopped" string to compare against anymore).
RECURSION_LIMIT = 2 * _MAX_AGENT_ITERATIONS + 2

# The rendered prompt (system prompt + the 10 bound tool schemas) is already ~2.2k tokens before any
# history: Ollama's default 2048-token context window silently truncates it from the start (observed
# live: "truncating input prompt" limit=2048 prompt=2174), dropping the system prompt and most tool
# schemas and wrecking tool selection. 8192 fits prompt + history + tool observations comfortably and
# keeps the prompt prefix stable across rounds, so follow-ups hit Ollama's KV prefix cache.
_NUM_CTX = 8192


def _parse_keep_alive(value: str) -> int | str:
    """Normalize the OLLAMA_KEEP_ALIVE setting to what ChatOllama/Ollama expect.

    Ollama's keep_alive is either an integer number of seconds (-1 keeps the model resident
    indefinitely, 0 unloads it immediately) or a Go-duration string like "5m"/"1h". The setting
    arrives as a string, so coerce a numeric value to int and pass any duration string through.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


@dataclass(frozen=True)
class ChatAgent:
    """A user-scoped chat agent: the compiled LangGraph runnable plus its tool-name registry.

    ``tool_names`` is carried alongside the runnable so the streaming consumer can gate which tool
    calls become a ``chat.status`` event without re-deriving the registry from the compiled graph.
    """

    runnable: Runnable
    tool_names: frozenset[str]


def build_agent(user, page_context: str = "") -> ChatAgent:
    """Build a tool-calling agent scoped to ``user``.

    ``ChatOllama`` is the local LLM; ``create_agent`` (the LangGraph agent runtime that replaced the
    deprecated ``AgentExecutor`` + ``create_tool_calling_agent``) binds the tools to the model via
    Ollama's native tool-calling API and runs the model -> tools -> model loop as a graph. The input
    is a ``{"messages": [...]}`` list (prior turns + the new user message), not the old
    ``{input, chat_history, agent_scratchpad}`` template dict.

    The system prompt is a plain string, so ``page_context`` (the compact "user is viewing job #N"
    hint) is appended here at build time rather than interpolated through a prompt template; when it
    is empty the base prompt is used verbatim. Streaming is chosen at call time (``runnable.stream``
    vs ``runnable.invoke``), so ``ChatOllama`` needs no ``streaming`` flag.

    Each built tool keeps ``handle_validation_error = on_invalid_tool_args`` (set in ``build_tools``):
    a schema-invalid argument the model emits becomes a recoverable observation instead of an
    exception that kills the turn — ``create_agent``'s tool node honors it because ``BaseTool``
    swallows the ``ValidationError`` before the node sees one.
    """
    llm = ChatOllama(
        model=settings.OLLAMA_MODEL,
        base_url=settings.OLLAMA_BASE_URL,
        temperature=0,
        num_ctx=_NUM_CTX,
        keep_alive=_parse_keep_alive(settings.OLLAMA_KEEP_ALIVE),
    )
    tools = build_tools(user=user)
    system_prompt = _SYSTEM_PROMPT if not page_context else f"{_SYSTEM_PROMPT}\n\n{page_context}"
    agent = create_agent(model=llm, tools=tools, system_prompt=system_prompt)
    return ChatAgent(runnable=agent, tool_names=frozenset(tool.name for tool in tools))


def final_answer(messages: list[BaseMessage]) -> str:
    """Return the assistant's terminal reply text from a finished run's ``messages``.

    ``create_agent`` ends when the model returns an ``AIMessage`` with no tool calls, so the final
    answer is the text of the last message when it carries no tool calls (otherwise the run did not
    reach a plain answer and there is nothing to persist). This is the source of truth the WebSocket
    ``chat.end`` and the REST reply both use.
    """
    if not messages:
        return ""
    last = messages[-1]
    if isinstance(last, AIMessage) and not last.tool_calls:
        return last.text
    return ""
