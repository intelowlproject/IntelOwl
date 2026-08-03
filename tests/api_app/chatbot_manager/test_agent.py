# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from typing import Any, Optional
from unittest.mock import patch

from django.conf import settings
from django.test import TestCase, override_settings
from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langgraph.errors import GraphRecursionError
from pydantic import PrivateAttr

from api_app.chatbot_manager.agent.agent import (
    _MAX_AGENT_ITERATIONS,
    _NUM_CTX,
    _SYSTEM_PROMPT,
    RECURSION_LIMIT,
    ChatAgent,
    _parse_keep_alive,
    build_agent,
    final_answer,
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


class _ScriptedChatModel(BaseChatModel):
    """Fake chat model that replays a scripted list of AIMessages, one per agent round.

    Stands in for ChatOllama inside ``create_agent`` without Ollama: ``bind_tools`` is a no-op
    (the responses are scripted, not derived from the bound tools) and each ``_generate`` returns
    the next scripted message (the last one repeats once the script is exhausted). Distinct message
    ids per round keep LangGraph's ``add_messages`` reducer appending rather than de-duplicating.
    """

    responses: list
    _i: int = PrivateAttr(default=0)

    @property
    def _llm_type(self) -> str:
        return "scripted-test"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: Optional[list[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        message = self.responses[min(self._i, len(self.responses) - 1)]
        self._i += 1
        return ChatResult(generations=[ChatGeneration(message=message)])


class _LoopingChatModel(BaseChatModel):
    """Fake chat model that NEVER stops: it re-calls one tool every round with a FRESH tool-call
    id (like a real model), so the run is a genuine runaway that force-stops at ``recursion_limit``
    rather than being collapsed by the id-deduping reducer.
    """

    tool_name: str
    tool_args: dict
    _i: int = PrivateAttr(default=0)

    @property
    def _llm_type(self) -> str:
        return "looping-test"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: Optional[list[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        self._i += 1
        message = AIMessage(
            content="",
            tool_calls=[{"name": self.tool_name, "args": self.tool_args, "id": f"call_{self._i}"}],
        )
        return ChatResult(generations=[ChatGeneration(message=message)])


class BuildAgentTestCase(TestCase):
    """``build_agent`` wires the full user-scoped tool registry and configures the local LLM."""

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chatbot_agent_user")

    def _build(self, **kwargs):
        # ChatOllama is mocked so no Ollama/network is ever touched; create_agent only needs the
        # mock's bind_tools() result to assemble the graph (it is not invoked here).
        with patch("api_app.chatbot_manager.agent.agent.ChatOllama") as mock_llm_cls:
            chat_agent = build_agent(user=self.user, **kwargs)
        return chat_agent, mock_llm_cls

    def test_agent_exposes_the_full_tool_registry(self):
        chat_agent, _ = self._build()
        self.assertIsInstance(chat_agent, ChatAgent)
        self.assertEqual(set(chat_agent.tool_names), EXPECTED_TOOL_NAMES)

    def test_llm_is_configured_for_local_ollama(self):
        _, mock_llm_cls = self._build()
        llm_kwargs = mock_llm_cls.call_args.kwargs
        self.assertEqual(llm_kwargs["model"], settings.OLLAMA_MODEL)
        self.assertEqual(llm_kwargs["base_url"], settings.OLLAMA_BASE_URL)
        self.assertEqual(llm_kwargs["temperature"], 0)
        # without an explicit context window Ollama truncates the multi-tool prompt
        self.assertEqual(llm_kwargs["num_ctx"], _NUM_CTX)

    def test_keep_alive_is_threaded_from_settings(self):
        _, mock_llm_cls = self._build()
        # default OLLAMA_KEEP_ALIVE "-1" is parsed to int -1 so Ollama keeps the model resident
        self.assertEqual(
            mock_llm_cls.call_args.kwargs["keep_alive"],
            _parse_keep_alive(settings.OLLAMA_KEEP_ALIVE),
        )

    @override_settings(OLLAMA_KEEP_ALIVE="5m")
    def test_keep_alive_duration_string_is_passed_through(self):
        _, mock_llm_cls = self._build()
        self.assertEqual(mock_llm_cls.call_args.kwargs["keep_alive"], "5m")

    def test_recursion_limit_maps_from_agent_rounds(self):
        # LangGraph counts supersteps, not agent rounds: one tool round is model->tools->model
        # (2 supersteps) plus the terminal model reply, plus LangGraph's boundary off-by-one.
        self.assertEqual(RECURSION_LIMIT, 2 * _MAX_AGENT_ITERATIONS + 2)

    def test_page_context_is_baked_into_the_system_prompt(self):
        with (
            patch("api_app.chatbot_manager.agent.agent.ChatOllama"),
            patch("api_app.chatbot_manager.agent.agent.create_agent") as mock_create,
        ):
            build_agent(user=self.user, page_context="The user is viewing job #42.")
            with_ctx = mock_create.call_args.kwargs["system_prompt"]
            build_agent(user=self.user)
            without_ctx = mock_create.call_args.kwargs["system_prompt"]
        self.assertIn(_SYSTEM_PROMPT, with_ctx)
        self.assertIn("The user is viewing job #42.", with_ctx)
        # no context -> exactly the base prompt (no dangling separator)
        self.assertEqual(without_ctx, _SYSTEM_PROMPT)


class AgentRunTestCase(TestCase):
    """End-to-end runs of the real create_agent graph with a scripted (Ollama-free) model."""

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chatbot_run_user")

    def _agent_with_model(self, fake_model):
        with patch("api_app.chatbot_manager.agent.agent.ChatOllama", return_value=fake_model):
            return build_agent(user=self.user)

    def _run(self, fake_model, message="hello"):
        chat_agent = self._agent_with_model(fake_model)
        return chat_agent.runnable.invoke(
            {"messages": [{"role": "user", "content": message}]},
            config={"recursion_limit": RECURSION_LIMIT},
        )

    def test_legit_conversation_completes_under_the_limit(self):
        # one tool round then a plain-text answer -> the run terminates well within RECURSION_LIMIT.
        call = AIMessage(content="", tool_calls=[{"name": "search_jobs", "args": {"limit": 5}, "id": "c1"}])
        answer = AIMessage(content="You have no recent jobs. (used: search_jobs)")
        result = self._run(_ScriptedChatModel(responses=[call, answer]), message="show my recent jobs")
        self.assertEqual(final_answer(result["messages"]), "You have no recent jobs. (used: search_jobs)")

    def test_runaway_model_force_stops_at_recursion_limit(self):
        # Authoritative bound for RECURSION_LIMIT: a model that keeps calling a tool must raise
        # GraphRecursionError (the caller maps it to ITERATION_LIMIT) instead of looping forever.
        looping = _LoopingChatModel(tool_name="search_jobs", tool_args={"limit": 5})
        chat_agent = self._agent_with_model(looping)
        with self.assertRaises(GraphRecursionError):
            chat_agent.runnable.invoke(
                {"messages": [{"role": "user", "content": "loop"}]},
                config={"recursion_limit": RECURSION_LIMIT},
            )


class FinalAnswerTestCase(TestCase):
    """`final_answer` returns the terminal assistant text, and only that."""

    def test_returns_last_ai_message_text(self):
        messages = [
            AIMessage(content="", tool_calls=[{"name": "x", "args": {}, "id": "1"}]),
            AIMessage(content="done"),
        ]
        self.assertEqual(final_answer(messages), "done")

    def test_empty_when_terminal_message_still_has_tool_calls(self):
        # defensive: a terminal message with tool calls is not a real answer.
        messages = [AIMessage(content="partial", tool_calls=[{"name": "x", "args": {}, "id": "1"}])]
        self.assertEqual(final_answer(messages), "")


class ToolArgRecoveryTestCase(TestCase):
    """A schema-invalid tool argument is recoverable, never a turn-killing exception."""

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chatbot_arg_recovery_user")

    def test_all_tools_handle_validation_errors(self):
        from api_app.chatbot_manager.agent.tools import build_tools

        for tool in build_tools(user=self.user):
            self.assertEqual(tool.handle_validation_error, on_invalid_tool_args)

    def test_invalid_tool_arg_is_recoverable_not_fatal(self):
        # round 1: model passes the literal placeholder -> ValidationError on job_id (an int),
        # surfaced as an on_invalid_tool_args observation. round 2: model answers in plain text.
        from langchain_core.messages import ToolMessage

        bad = AIMessage(
            content="", tool_calls=[{"name": "summarize_job", "args": {"job_id": "<job_id>"}, "id": "c1"}]
        )
        answer = AIMessage(content="Here is the summary.")
        with patch(
            "api_app.chatbot_manager.agent.agent.ChatOllama",
            return_value=_ScriptedChatModel(responses=[bad, answer]),
        ):
            chat_agent = build_agent(user=self.user)
        result = chat_agent.runnable.invoke(
            {"messages": [{"role": "user", "content": "summarize my latest job"}]},
            config={"recursion_limit": RECURSION_LIMIT},
        )
        self.assertEqual(final_answer(result["messages"]), "Here is the summary.")
        # index (not next()) so a missing observation fails loudly here, not with a bare StopIteration
        observations = [m for m in result["messages"] if isinstance(m, ToolMessage)]
        self.assertTrue(observations)
        self.assertIn("Invalid tool arguments", observations[0].content)

    def test_persistent_invalid_arg_degrades_to_forced_stop(self):
        # The model emits the bad placeholder on every round: instead of crashing it must
        # force-stop at recursion_limit (GraphRecursionError -> ITERATION_LIMIT for the caller).
        looping = _LoopingChatModel(tool_name="summarize_job", tool_args={"job_id": "<job_id>"})
        with patch("api_app.chatbot_manager.agent.agent.ChatOllama", return_value=looping):
            chat_agent = build_agent(user=self.user)
        with self.assertRaises(GraphRecursionError):
            chat_agent.runnable.invoke(
                {"messages": [{"role": "user", "content": "summarize my latest job"}]},
                config={"recursion_limit": RECURSION_LIMIT},
            )

    def test_system_prompt_warns_against_placeholder_args(self):
        # guard the specific rule, not just the word: the <job_id> token appears only in it
        self.assertIn("<job_id>", _SYSTEM_PROMPT)
        self.assertIn("placeholder", _SYSTEM_PROMPT.lower())


class OnInvalidToolArgsTestCase(TestCase):
    """The observation returned on a bad tool argument names the error and steers a retry."""

    def test_message_surfaces_error_and_forbids_placeholders(self):
        msg = on_invalid_tool_args(ValueError("job_id: not an integer"))
        self.assertIsInstance(msg, str)
        self.assertIn("job_id: not an integer", msg)  # the underlying error reaches the model
        self.assertIn("placeholder", msg.lower())  # tell it not to pass a placeholder


class SystemPromptToolRoutingTestCase(TestCase):
    """String-level guard for the #3843 jobs-vs-investigations routing cues.

    The behavioral evidence is the tool-selection reliability harness re-run (documented in the
    benchmark report), not this test; it only locks the specific prompt cues and rule the harness
    validated so a later prompt edit can't silently drop them. It never touches Ollama.
    """

    def test_jobs_questions_are_anchored_to_search_jobs(self):
        lower = _SYSTEM_PROMPT.lower()
        # the phrasing that mis-routed to list_investigations 0/10 is now an explicit search_jobs cue
        self.assertIn("what jobs do i have?", lower)
        # the directional rule steering "own jobs" questions to search_jobs (not list_investigations)
        self.assertIn("jobs vs investigations", lower)
        self.assertIn("search_jobs", _SYSTEM_PROMPT)


class SystemPromptVerdictRoutingTestCase(TestCase):
    """Both former quick-action intents ("summarize" and "evaluate") must land on summarize_job.

    The verdict was folded into summarize_job instead of getting its own tool, so there is no
    routing decision left for the model to get wrong; this test only guarantees the prompt keeps
    advertising both phrasings on that one tool. It never touches Ollama.
    """

    def test_summarize_and_evaluate_intents_share_one_tool(self):
        lower = _SYSTEM_PROMPT.lower()
        # Collected rather than `next()`-ed: a bare next() raises StopIteration if the cue is ever
        # renamed, which reads as a crash instead of a failed assertion. The count is asserted too,
        # since a second summarize_job cue would make the routing ambiguous.
        summarize_cues = [line for line in lower.splitlines() if line.startswith("- summarize_job:")]
        self.assertEqual(len(summarize_cues), 1, f"expected one summarize_job cue, got {summarize_cues}")
        summarize_cue = summarize_cues[0]
        self.assertIn("summarize job #n", summarize_cue)
        self.assertIn("evaluate the results of job #n", summarize_cue)
        self.assertIn("is job #n malicious?", summarize_cue)
        # no evaluate_job tool exists: the fold is the whole point
        self.assertNotIn("evaluate_job", lower)

    def test_prompt_tells_the_model_what_to_relay_from_the_verdict(self):
        """The narration contract the live smoke (Task 5) measures: headline first, then counts.

        A structured `verdict` object only helps if the model actually reads the fields; the
        prompt is the only lever for that, so the three field names are pinned here.
        """
        lower = _SYSTEM_PROMPT.lower()
        self.assertIn("headline", lower)
        self.assertIn("supporting", lower)
        self.assertIn("silent", lower)


class ParseKeepAliveTestCase(TestCase):
    """OLLAMA_KEEP_ALIVE is coerced to what Ollama expects: int seconds or a duration string."""

    def test_numeric_strings_become_ints(self):
        self.assertEqual(_parse_keep_alive("-1"), -1)
        self.assertEqual(_parse_keep_alive("300"), 300)
        self.assertEqual(_parse_keep_alive("0"), 0)

    def test_duration_strings_pass_through(self):
        self.assertEqual(_parse_keep_alive("5m"), "5m")
        self.assertEqual(_parse_keep_alive("1h"), "1h")
