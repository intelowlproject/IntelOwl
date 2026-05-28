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

REACT_PROMPT = PromptTemplate.from_template(_SYSTEM_PROMPT)


def build_agent_executor(user) -> AgentExecutor:
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
