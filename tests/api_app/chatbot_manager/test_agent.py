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
    _SYSTEM_PROMPT,
    AGENT_STOPPED_OUTPUT,
    build_agent_executor,
)
from api_app.chatbot_manager.agent.tools._common import on_invalid_tool_args
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

        result = executor.invoke({"input": "loop forever", "chat_history": [], "page_context": ""})

        self.assertEqual(result["output"], AGENT_STOPPED_OUTPUT)


class OnInvalidToolArgsTestCase(TestCase):
    """The observation returned on a bad tool argument names the error and steers a retry."""

    def test_message_surfaces_error_and_forbids_placeholders(self):
        msg = on_invalid_tool_args(ValueError("job_id: not an integer"))
        self.assertIsInstance(msg, str)
        self.assertIn("job_id: not an integer", msg)  # the underlying error reaches the model
        self.assertIn("placeholder", msg.lower())  # tell it not to pass a placeholder


def _scripted_llm(responses):
    """Fake ChatOllama whose bound runnable replays `responses`, one AIMessage per agent round."""
    replies = iter(responses)
    llm = MagicMock()
    # next() takes a default so an exhausted script can't raise StopIteration (DeepSource PTC-W0063):
    # returning a plain-text AIMessage ends the agent loop benignly instead of crashing the test.
    llm.bind_tools.return_value = RunnableLambda(lambda _: next(replies, AIMessage(content="")))
    return llm


class ToolArgRecoveryTestCase(TestCase):
    """A schema-invalid tool argument is recoverable, never a turn-killing exception."""

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chatbot_arg_recovery_user")

    def test_all_tools_handle_validation_errors(self):
        with patch("api_app.chatbot_manager.agent.agent.ChatOllama"):
            executor = build_agent_executor(user=self.user)
        for tool in executor.tools:
            self.assertEqual(tool.handle_validation_error, on_invalid_tool_args)

    def test_invalid_tool_arg_is_recoverable_not_fatal(self):
        # round 1: model passes the literal placeholder -> ValidationError on job_id (an int).
        # round 2: model answers in plain text. The turn must complete, not raise.
        bad = AIMessage(
            content="", tool_calls=[{"name": "summarize_job", "args": {"job_id": "<job_id>"}, "id": "c1"}]
        )
        answer = AIMessage(content="Here is the summary.")
        llm = _scripted_llm([bad, answer])
        with patch("api_app.chatbot_manager.agent.agent.ChatOllama", return_value=llm):
            executor = build_agent_executor(user=self.user)
        result = executor.invoke({"input": "summarize my latest job", "chat_history": [], "page_context": ""})
        self.assertEqual(result["output"], "Here is the summary.")

    def test_persistent_invalid_arg_degrades_to_forced_stop(self):
        # The model emits the bad placeholder on every round: instead of crashing it must
        # force-stop at max_iterations (the sentinel the caller maps to ITERATION_LIMIT).
        bad = AIMessage(
            content="", tool_calls=[{"name": "summarize_job", "args": {"job_id": "<job_id>"}, "id": "c1"}]
        )
        llm = MagicMock()
        llm.bind_tools.return_value = RunnableLambda(lambda _: bad)
        with patch("api_app.chatbot_manager.agent.agent.ChatOllama", return_value=llm):
            executor = build_agent_executor(user=self.user)
        result = executor.invoke({"input": "summarize my latest job", "chat_history": [], "page_context": ""})
        self.assertEqual(result["output"], AGENT_STOPPED_OUTPUT)

    def test_system_prompt_warns_against_placeholder_args(self):
        # guard the specific rule, not just the word: the <job_id> token appears only in it
        self.assertIn("<job_id>", _SYSTEM_PROMPT)
        self.assertIn("placeholder", _SYSTEM_PROMPT.lower())
