# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from dataclasses import asdict, dataclass, field
from types import SimpleNamespace
from typing import List, Optional

from langchain_core.tools import tool

from api_app.chatbot_manager.serializers.analyze_observable import AnalyzeObservableResultSerializer
from api_app.choices import TLP, ScanMode
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers.job import ObservableAnalysisSerializer


@dataclass
class _AnalysisPlan:
    """Preview of what a confirmed analyze_observable call would launch.

    Computed (non-model) data, so it is a typed dataclass rather than a free-form dict (Matteo's
    rule); `asdict()` converts it only at the serializer boundary.
    """

    observable_name: str
    classification: str
    tlp: str
    playbook: Optional[str]
    analyzers: List[str]
    connectors: List[str]
    skipped: List[str] = field(default_factory=list)


def _flatten_errors(errors) -> List[str]:
    """Flatten DRF's ``{field: [msg, ...]}`` error dict into a flat ``list[str]``.

    The reused serializer reports failures (private-IP guardrail, unknown analyzer, "nothing
    runnable", ...) as nested ``ValidationError`` dicts; the LLM only needs a flat list of messages.
    """
    if isinstance(errors, dict):
        flat = []
        for field_name, messages in errors.items():
            if isinstance(messages, (list, tuple)):
                flat.extend(f"{field_name}: {message}" for message in messages)
            else:
                flat.append(f"{field_name}: {messages}")
        return flat
    if isinstance(errors, (list, tuple)):
        return [str(message) for message in errors]
    return [str(errors)]


def make_analyze_observable_tool(user):
    # Built per-request and closed over `user`. This is the only ACTION tool: it can launch a real
    # IntelOwl analysis. Safety is two-phase + confirm-gated -- a call without confirm=True can never
    # reach `job_pipeline.apply_async`, because the create path triggers it only under
    # `save(send_task=True)`, which we call exclusively on the confirm=True branch. The created
    # `Job.user` is this closured `user` (via the request shim), so the agent cannot widen scope.
    @tool("analyze_observable")
    def analyze_observable(
        observable_name: str,
        playbook: str = "",
        analyzers: str = "",
        tlp: str = TLP.CLEAR.value,
        confirm: bool = False,
    ) -> str:
        """Start a new IntelOwl analysis of an observable (IP, domain, URL, hash, ...).

        This tool ACTUALLY launches an analysis, so it is two-phase and must be confirmed:
        1. Call it first with confirm=false -> it validates the request and returns a `plan` (the
           analyzers/connectors that would run, the ones skipped, the resolved classification)
           WITHOUT starting anything. Show that plan to the user.
        2. Only after the user explicitly approves, call it again with the same arguments and
           confirm=true -> this starts the job.

        Args:
            observable_name: The observable to analyze (an IP, domain, URL or hash).
            playbook: Optional playbook name to run (must be visible to you). Mutually exclusive
                    with `analyzers`.
            analyzers: Optional COMMA-SEPARATED analyzer names (e.g. "Classic_DNS,VirusTotal_v3").
                    Mutually exclusive with `playbook`. If both are empty the instance defaults run.
            tlp: Traffic Light Protocol level (CLEAR, GREEN, AMBER, RED; default CLEAR). TLP only
                    filters which plugins may run -- it never blocks the launch.
            confirm: Must be true to actually start the analysis. Defaults to false (preview only).

        Returns:
            JSON string with shape {"errors": [...], "confirmation_required": bool,
            "plan": {...} | null, "job": {...} | null}.
        """
        # The reused serializer reads the requesting user from `context["request"].user`; a shim is
        # enough since the create path only ever reads `.user`.
        shim = SimpleNamespace(user=user)
        # FORCE_NEW_ANALYSIS (not the platform default CHECK_PREVIOUS_ANALYSIS): confirm=True always
        # starts a fresh job rather than possibly returning a cached one -> deterministic contract.
        data = {
            "observable_name": observable_name,
            "tlp": tlp,
            "scan_mode": ScanMode.FORCE_NEW_ANALYSIS.value,
        }

        if playbook:
            # ISOLATION GUARD: ObservableAnalysisSerializer resolves `playbook_requested` via
            # PlaybookConfig.objects.all() (no visibility filter) and the create path never re-scopes
            # it -- so an LLM-supplied name could reference another org's PRIVATE playbook and leak
            # its existence/composition into the plan. Scope it here against `visible_for_user` (the
            # same boundary recommend_playbook uses) BEFORE the serializer sees it. Analyzers need no
            # such guard: AnalyzerConfig is a global config (matches the UI's `.all()`).
            if not PlaybookConfig.objects.visible_for_user(user).filter(name=playbook).exists():
                return AnalyzeObservableResultSerializer(
                    {
                        "errors": [f"Playbook '{playbook}' not found or not visible to you."],
                        "confirmation_required": False,
                        "plan": None,
                        "job": None,
                    }
                ).to_json()
            data["playbook_requested"] = playbook

        # The agent is the string-based ReAct agent (one `Action Input` string), so `analyzers` is a
        # comma-separated string split here rather than a JSON list (unreliable for a small model).
        analyzers_list = [a.strip() for a in analyzers.split(",") if a.strip()]
        if analyzers_list:
            data["analyzers_requested"] = analyzers_list

        serializer = ObservableAnalysisSerializer(data=data, context={"request": shim})
        if not serializer.is_valid(raise_exception=False):
            return AnalyzeObservableResultSerializer(
                {
                    "errors": _flatten_errors(serializer.errors),
                    "confirmation_required": False,
                    "plan": None,
                    "job": None,
                }
            ).to_json()

        validated = serializer.validated_data
        if not confirm:
            # Preview path: report exactly what a confirmed call would run; trigger nothing.
            plan = _AnalysisPlan(
                observable_name=validated["observable_name"],
                classification=validated["observable_classification"],
                tlp=validated["tlp"],
                playbook=validated["playbook_requested"].name
                if validated.get("playbook_requested")
                else None,
                analyzers=[analyzer.name for analyzer in validated["analyzers_to_execute"]],
                connectors=[connector.name for connector in validated["connectors_to_execute"]],
                # the committed copy of the serializer's filter_warnings (skipped/unrunnable plugins)
                skipped=list(validated.get("warnings", [])),
            )
            return AnalyzeObservableResultSerializer(
                {"errors": [], "confirmation_required": True, "plan": asdict(plan), "job": None}
            ).to_json()

        # confirm=True: the ONLY path that triggers the analysis (job_pipeline.apply_async, via
        # save(send_task=True)).
        job = serializer.save(send_task=True)
        return AnalyzeObservableResultSerializer(
            {"errors": [], "confirmation_required": False, "plan": None, "job": job}
        ).to_json()

    return analyze_observable
