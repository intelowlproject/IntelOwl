# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

from django.conf import settings
from django.test import TestCase
from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda

from api_app.chatbot_manager.agent.agent import (
    _MAX_AGENT_ITERATIONS,
    _NUM_CTX,
    AGENT_STOPPED_OUTPUT,
    build_agent_executor,
)
from certego_saas.apps.user.models import User

# The full tool registry the agent must expose (one factory per module in agent/tools/).
EXPECTED_TOOL_NAMES = {
    "search_jobs",
    "get_job_details",
    "summarize_job",
    "list_investigations",
    "get_investigation_tree",
    "summarize_investigation",
    "get_data_model",
    "list_analyzers",
    "recommend_playbook",
    "analyze_observable",
}


class BuildAgentExecutorTestCase(TestCase):
    """The executor wires the full user-scoped tool registry and bounds the agent loop."""

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chatbot_agent_user")

    def _build(self, **kwargs):
        # ChatOllama is mocked so no Ollama/network is ever touched; create_tool_calling_agent
        # only needs the mock's bind_tools() result to be composable into its runnable chain.
        with patch("api_app.chatbot_manager.agent.agent.ChatOllama") as mock_llm_cls:
            executor = build_agent_executor(user=self.user, **kwargs)
        return executor, mock_llm_cls

    def test_executor_has_all_tools_and_a_bounded_loop(self):
        executor, _ = self._build()

        self.assertEqual({tool.name for tool in executor.tools}, EXPECTED_TOOL_NAMES)
        # max_iterations is the only bound that force-stops a looping model
        self.assertEqual(executor.max_iterations, _MAX_AGENT_ITERATIONS)
        self.assertTrue(executor.handle_parsing_errors)

    def test_streaming_flag_reaches_the_llm(self):
        for streaming in (False, True):
            with self.subTest(streaming=streaming):
                _, mock_llm_cls = self._build(streaming=streaming)
                llm_kwargs = mock_llm_cls.call_args.kwargs
                self.assertEqual(llm_kwargs["streaming"], streaming)
                self.assertEqual(llm_kwargs["model"], settings.OLLAMA_MODEL)
                self.assertEqual(llm_kwargs["base_url"], settings.OLLAMA_BASE_URL)
                # without an explicit context window Ollama truncates the multi-tool prompt
                self.assertEqual(llm_kwargs["num_ctx"], _NUM_CTX)

    def test_forced_stop_output_matches_the_sentinel(self):
        # Ties AGENT_STOPPED_OUTPUT to the real framework behavior: the executor is the real
        # tool-calling pipeline, only the LLM is faked to request a tool on every round, so
        # max_iterations force-stops it. A langchain bump that changes the canned stop message
        # must fail here rather than silently persist it as an assistant answer.
        tool_call_forever = AIMessage(
            content="",
            tool_calls=[{"name": "search_jobs", "args": {"query": ""}, "id": "call_1"}],
        )
        llm = MagicMock()
        llm.bind_tools.return_value = RunnableLambda(lambda _: tool_call_forever)
        with patch("api_app.chatbot_manager.agent.agent.ChatOllama", return_value=llm):
            executor = build_agent_executor(user=self.user)

        result = executor.invoke({"input": "loop forever", "chat_history": []})

        self.assertEqual(result["output"], AGENT_STOPPED_OUTPUT)
