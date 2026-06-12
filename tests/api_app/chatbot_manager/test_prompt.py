# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Structural tests for the agent system prompt file.

These tests verify that system_prompt.txt is loadable, within token limits,
and covers all registered tools — no LLM inference is performed.
"""

from pathlib import Path

from django.test import TestCase

from api_app.chatbot_manager.agent.agent import _SYSTEM_PROMPT, PROMPT
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
        """System prompt must stay under 500 tokens to leave room for tool schemas
        and conversation history within Ollama's 8192 context window.
        """
        tokens = len(_SYSTEM_PROMPT.split())
        self.assertLess(tokens, 500, f"system prompt is {tokens} tokens — exceeds 500")

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

    def test_prompt_is_part_of_the_chat_template(self):
        """The loaded prompt content is embedded in the ChatPromptTemplate's
        system message, so the agent actually sees the file content at runtime.
        """
        # PROMPT.messages[0] is a SystemMessagePromptTemplate; its .prompt.template
        # carries the system text (with {page_context} appended).
        system_msg = PROMPT.messages[0]
        template = system_msg.prompt.template
        self.assertIn(_SYSTEM_PROMPT, template)

    def test_prompt_sections_are_present(self):
        """Each planned section header appears so the structure is enforced."""
        for section in ("[Role]", "[Tools", "[Rules]", "[Response style]"):
            self.assertIn(section, _SYSTEM_PROMPT, f"Missing section: {section}")

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
