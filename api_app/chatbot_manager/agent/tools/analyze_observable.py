# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from types import SimpleNamespace

from langchain_core.tools import tool

from api_app.chatbot_manager.pending_action import create_pending_analysis
from api_app.chatbot_manager.serializers.analyze_observable import (
    AnalyzeObservableResultSerializer,
    flatten_errors,
)
from api_app.choices import TLP
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers.job import ObservableAnalysisSerializer


def make_analyze_observable_tool(user):
    # Built per-request and closed over `user`. This is the only action-capable tool, but it now
    # NEVER launches: it validates and returns a `plan` plus a one-time `pending_id`. The actual
    # launch happens only when the user confirms via the chat panel (POST /api/chatbot/analysis/
    # confirm), so a misbehaving model can never start an analysis on its own (guardrail M-1).
    @tool("analyze_observable")
    def analyze_observable(
        observable_name: str,
        playbook: str = "",
        analyzers: str = "",
        tlp: str = TLP.CLEAR.value,
    ) -> str:
        """Preview an IntelOwl analysis of an observable (IP, domain, URL, hash).

        This tool does NOT start anything: it validates the request and returns the `plan` that
        would run plus a `pending_id`. Tell the user to approve it with the Confirm button in the
        chat panel; you cannot launch the analysis yourself.

        Args:
            observable_name: The observable to analyze (an IP, domain, URL or hash).
            playbook: Optional playbook name (must be visible to you). Mutually exclusive with analyzers.
            analyzers: Optional COMMA-SEPARATED analyzer names. Mutually exclusive with playbook.
            tlp: TLP level (CLEAR, GREEN, AMBER, RED; default CLEAR). Only filters which plugins run.

        Returns:
            JSON string {"errors": [...], "plan": {...} | null, "pending_id": "..." | null}.
        """
        shim = SimpleNamespace(user=user)
        if playbook:
            # ISOLATION GUARD: ObservableAnalysisSerializer resolves playbook_requested via
            # PlaybookConfig.objects.all() with no visibility filter; scope it here first so another
            # org's private playbook can't leak into the plan.
            if not PlaybookConfig.objects.visible_for_user(user).filter(name=playbook).exists():
                return AnalyzeObservableResultSerializer(
                    {
                        "errors": [f"Playbook '{playbook}' not found or not visible to you."],
                        "plan": None,
                        "pending_id": None,
                    }
                ).to_json()

        data = {"observable_name": observable_name, "tlp": tlp}
        if playbook:
            data["playbook_requested"] = playbook
        analyzers_list = [a.strip() for a in analyzers.split(",") if a.strip()]
        if analyzers_list:
            data["analyzers_requested"] = analyzers_list

        serializer = ObservableAnalysisSerializer(data=data, context={"request": shim})
        if not serializer.is_valid(raise_exception=False):
            return AnalyzeObservableResultSerializer(
                {"errors": flatten_errors(serializer.errors), "plan": None, "pending_id": None}
            ).to_json()

        validated = serializer.validated_data
        plan = {
            "observable_name": validated["observable_name"],
            "classification": validated["observable_classification"],
            "tlp": validated["tlp"],
            "playbook": validated["playbook_requested"].name if validated.get("playbook_requested") else None,
            "analyzers": [analyzer.name for analyzer in validated["analyzers_to_execute"]],
            "connectors": [connector.name for connector in validated["connectors_to_execute"]],
            "skipped": list(validated.get("warnings", [])),
        }
        # Store the RAW inputs (re-validated at confirm time); the model cannot launch -- only a
        # user POST of this pending_id to the confirm endpoint can.
        pending_id = create_pending_analysis(
            user.id,
            {"observable_name": observable_name, "tlp": tlp, "playbook": playbook, "analyzers": analyzers},
        )
        return AnalyzeObservableResultSerializer(
            {"errors": [], "plan": plan, "pending_id": pending_id}
        ).to_json()

    return analyze_observable
