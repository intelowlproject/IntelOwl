# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from pathlib import Path

from django.conf import settings
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_ollama import ChatOllama

from .tools import build_tools

# The system prompt lives in its own text file so it is readable, testable, and
# editable without touching Python code. {page_context} is appended separately by
# the prompt template below so the file stays self-contained (no interpolation).
_SYSTEM_PROMPT = Path(__file__).parent.joinpath("system_prompt.txt").read_text(encoding="utf-8").strip()

# The agent uses Ollama's native tool-calling API (`llm.bind_tools`, wired by
# `create_tool_calling_agent`), so the prompt carries no rendered tool list and no ReAct
# Thought/Action/Final Answer text scaffolding: the model emits structured tool calls and the
# executor loops tool call -> observation under the hood. `chat_history` and `agent_scratchpad`
# are message lists (MessagesPlaceholder), not pre-rendered text.
PROMPT = ChatPromptTemplate.from_messages(
    [
        ("system", _SYSTEM_PROMPT + "\n\n{page_context}"),
        MessagesPlaceholder("chat_history"),
        ("human", "{input}"),
        MessagesPlaceholder("agent_scratchpad"),
    ]
)

# One iteration = one round of tool calls + observation. Real questions resolve in 1-3 rounds
# (analyze_observable's confirm flow spans two turns, not two iterations), so 6 leaves room for
# a retry after a failed call while force-stopping a looping model well before the Celery task's
# 300s soft time limit would on CPU.
_MAX_AGENT_ITERATIONS = 6

# What AgentExecutor returns as "output" when max_iterations force-stops the run (the
# multi-action agent's return_stopped_response, langchain 0.3.25). Callers compare against this
# to turn a forced stop into a user-facing error instead of persisting the canned framework
# string as an assistant message.
AGENT_STOPPED_OUTPUT = "Agent stopped due to max iterations."

# The rendered prompt (system prompt + the 10 bound tool schemas) is already ~2.2k tokens
# before any history: Ollama's default 2048-token context window silently truncates it from
# the start (observed live: "truncating input prompt" limit=2048 prompt=2174), dropping the
# system prompt and most tool schemas and wrecking tool selection. 8192 fits prompt + history
# + tool observations comfortably and keeps the prompt prefix stable across iterations, so
# follow-up rounds hit Ollama's KV prefix cache instead of re-evaluating everything.
_NUM_CTX = 8192


def build_agent_executor(user, streaming: bool = False) -> AgentExecutor:
    """Build a tool-calling agent executor scoped to `user`.

    `ChatOllama` is the local LLM; `create_tool_calling_agent` binds the tools to the model
    through the native tool-calling API — there is no text format to parse, which is what made
    the previous string-ReAct loop unreliable on small local models (they rarely emit a
    parseable `Final Answer:` line). `AgentExecutor` runs the tool-call -> observation loop
    until the model replies with plain text. `handle_parsing_errors=True` feeds an unparseable
    model output back as an observation instead of raising (it does NOT cover schema-invalid
    tool *arguments*, which raise from the tool itself and surface through the caller's generic
    error handling); `max_iterations` bounds a looping model (`early_stopping_method` stays at
    its default "force" — runnable agents support no other value in langchain 0.3, "generate"
    raises ValueError).

    `streaming=True` makes `ChatOllama` emit token-level callbacks so the WebSocket path can
    stream the answer live. No callbacks are bound to the model here: the caller attaches them
    per run (`executor.invoke(..., config={"callbacks": [...]})`) so they also receive the
    agent's tool actions, which originate from the executor and not from the LLM.
    """
    llm = ChatOllama(
        model=settings.OLLAMA_MODEL,
        base_url=settings.OLLAMA_BASE_URL,
        temperature=0,
        num_ctx=_NUM_CTX,
        streaming=streaming,
    )
    tools = build_tools(user=user)
    agent = create_tool_calling_agent(llm, tools, PROMPT)
    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=False,
        handle_parsing_errors=True,
        max_iterations=_MAX_AGENT_ITERATIONS,
    )
