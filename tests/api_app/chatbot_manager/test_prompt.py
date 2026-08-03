# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Structural tests for the agent system prompt file.

These tests verify that system_prompt.txt is loadable, within token limits,
and covers all registered tools — no LLM inference is performed.
"""

from pathlib import Path
from unittest.mock import patch

from django.test import TestCase

from api_app.chatbot_manager.agent.agent import _SYSTEM_PROMPT, build_agent
from api_app.chatbot_manager.agent.tools import build_tools
from certego_saas.apps.user.models import User

PROMPT_FILE = Path(__file__).parent.parent.parent.parent.joinpath(
    "api_app", "chatbot_manager", "agent", "system_prompt.txt"
)

# The 10 tool names the prompt MUST mention so the model knows when to use each.
# Keeping this set in the test forces the author to update the prompt when tools
# are added or removed from build_tools().
EXPECTED_TOOL_NAMES = frozenset(
    {
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
)


class SystemPromptTestCase(TestCase):
    def test_prompt_file_readable(self):
        """The file exists and loads into the module-level constant."""
        self.assertTrue(PROMPT_FILE.exists(), f"Missing: {PROMPT_FILE}")
        self.assertIsInstance(_SYSTEM_PROMPT, str)
        self.assertGreater(len(_SYSTEM_PROMPT), 100)
        stripped = _SYSTEM_PROMPT.strip()
        self.assertEqual(
            stripped,
            _SYSTEM_PROMPT,
            "system prompt contains leading/trailing whitespace",
        )

    def test_prompt_under_token_limit(self):
        """Cap the prompt so the tool schemas and the conversation history still fit in
        Ollama's 8192-token context window.

        The bound counts whitespace-separated WORDS, not tokens — for this text roughly 1.3-1.4
        tokens per word, so 600 words is about 850 tokens, near a tenth of the window. The
        original 500 was set when the prompt was 430 words; it had shrunk to 8 words of headroom
        and was rejecting further rules rather than protecting the window, so it is raised here
        together with the rule that needed the room.
        """
        words = len(_SYSTEM_PROMPT.split())
        self.assertLess(words, 600, f"system prompt is {words} words — exceeds 600")

    def test_prompt_includes_all_tool_names(self):
        """Every registered tool appears in the [Tools] section, and the hardcoded
        EXPECTED_TOOL_NAMES matches the live build_tools() registry. If someone adds
        a tool without updating both this test and system_prompt.txt, this catches it.
        """
        user, _ = User.objects.get_or_create(username="prompt_tool_user")
        registered = frozenset(tool.name for tool in build_tools(user=user))
        self.assertEqual(
            registered,
            EXPECTED_TOOL_NAMES,
            "Tool registry changed — update EXPECTED_TOOL_NAMES and system_prompt.txt",
        )

        for name in EXPECTED_TOOL_NAMES:
            self.assertIn(
                name,
                _SYSTEM_PROMPT,
                f"Tool '{name}' not found in system_prompt.txt — add it to the [Tools] section",
            )

    def test_prompt_is_passed_to_the_agent(self):
        """build_agent hands the file content to create_agent as the system prompt, so the agent
        actually sees it at runtime (ChatOllama/create_agent are mocked — no Ollama is touched).
        """
        user, _ = User.objects.get_or_create(username="prompt_build_user")
        with (
            patch("api_app.chatbot_manager.agent.agent.ChatOllama"),
            patch("api_app.chatbot_manager.agent.agent.create_agent") as mock_create,
        ):
            build_agent(user=user)
        self.assertIn(_SYSTEM_PROMPT, mock_create.call_args.kwargs["system_prompt"])

    def test_prompt_sections_are_present(self):
        """Each planned section header appears so the structure is enforced."""
        for section in ("[Role]", "[Tools", "[Rules]", "[Response style]"):
            self.assertIn(section, _SYSTEM_PROMPT, f"Missing section: {section}")

    def test_prompt_forbids_placeholder_names(self):
        """A2: the [Rules] section must tell the model to copy analyzer/playbook/job names verbatim
        and never emit bracketed placeholders like [Analyzer 1] — the qwen2.5:3b failure @mlodic hit.
        """
        lowered = _SYSTEM_PROMPT.lower()
        self.assertIn("verbatim", lowered)
        self.assertIn("placeholder", lowered)

    def test_prompt_tells_model_to_surface_plan_reason(self):
        """F2: the plan carries a `reason` when analyze_observable defaults a playbook, but the model
        only narrates it if the prompt says to. The [Rules] section must instruct it to report the
        reason in the confirmation message.
        """
        lowered = _SYSTEM_PROMPT.lower()
        self.assertIn("reason", lowered)
        self.assertIn("why that playbook was chosen", lowered)

    def test_page_context_not_in_the_file(self):
        """The file must NOT contain {page_context} — interpolation is the prompt
        template's job, not the static file's.
        """
        self.assertNotIn("{page_context}", _SYSTEM_PROMPT)

    def test_prompt_is_all_printable(self):
        """Non-printable characters (except newline) will silently confuse the LLM."""
        self.assertNotIn("\r", _SYSTEM_PROMPT)
        self.assertTrue(
            all(c.isprintable() or c == "\n" for c in _SYSTEM_PROMPT),
            "system prompt contains non-printable characters",
        )
