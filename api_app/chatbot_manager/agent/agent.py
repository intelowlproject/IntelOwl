# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.prompts import PromptTemplate
from langchain_ollama import ChatOllama

from .tools import build_tools

_SYSTEM_PROMPT = """\
You are IntelOwl AI, an intelligent assistant for the IntelOwl threat intelligence platform.
You help security analysts query and interpret threat intelligence data.
Only access data belonging to the current user. Never reveal other users' data.
The analyze_observable tool starts a real analysis: always call it first with confirm=false, show the returned plan to the user, and only call it again with confirm=true after the user explicitly approves.

You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Previous conversation:
{chat_history}

Question: {input}
{agent_scratchpad}"""

# The prompt drives the ReAct loop. `create_react_agent` fills in the placeholders:
# `{tools}`/`{tool_names}` are rendered from the tool list, and `{agent_scratchpad}` is
# where the model's own Thought/Action/Observation steps are accumulated across iterations.
REACT_PROMPT = PromptTemplate.from_template(_SYSTEM_PROMPT)


def build_agent_executor(user) -> AgentExecutor:
    """Build a ReAct agent executor scoped to `user`.

    `ChatOllama` is the local LLM; `create_react_agent` wires the model + tools + prompt
    into a reasoning loop (Thought → Action → Observation → ...); `AgentExecutor` runs
    that loop until a Final Answer. `handle_parsing_errors=True` makes the executor feed
    a malformed model output back as an Observation instead of raising, which keeps small
    local models from crashing the turn on a formatting slip.
    """
    llm = ChatOllama(
        model=settings.OLLAMA_MODEL,
        base_url=settings.OLLAMA_BASE_URL,
        temperature=0,
    )
    tools = build_tools(user=user)
    agent = create_react_agent(llm, tools, REACT_PROMPT)
    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=False,
        handle_parsing_errors=True,
    )


def format_history(messages: list) -> str:
    """Serialize LangChain message list to plain text for prompt injection."""
    lines = []
    for msg in messages:
        if isinstance(msg, HumanMessage):
            lines.append(f"User: {msg.content}")
        elif isinstance(msg, AIMessage):
            lines.append(f"Assistant: {msg.content}")
    return "\n".join(lines) if lines else ""
