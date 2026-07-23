# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from types import SimpleNamespace

from langchain_core.tools import tool

from api_app.chatbot_manager.pending_action import create_pending_analysis
from api_app.chatbot_manager.serializers.analyze_observable import (
    AnalyzeObservableResultSerializer,
    flatten_errors,
)
from api_app.choices import TLP, Classification
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers.job import ObservableAnalysisSerializer

# IntelOwl actively curates this playbook for plugins that need no API key (many migrations add
# analyzers to it), so it is the safe default when the user names neither a playbook nor analyzers.
FREE_TO_USE_PLAYBOOK = "FREE_TO_USE_ANALYZERS"
# Cap the playbook list in the fallback error so the LLM-facing message stays compact and actionable
# (visible_for_user includes every public playbook, so a classification can match dozens).
_MAX_PLAYBOOKS_IN_ERROR = 20


def _resolve_default_playbook(user, observable_name: str) -> tuple[str | None, str]:
    """Resolve the default playbook for an observable the model gave no plugins for.

    Kept out of the tool closure so the closure stays under the cyclomatic-complexity gate and the
    resolution is unit-testable on its own. Scoped to ``user`` via ``visible_for_user``, so it adds
    no tenancy boundary.

    Returns ``(playbook_name, reason)`` when the curated ``FREE_TO_USE_ANALYZERS`` playbook is
    visible, applicable to the classification and enabled. Otherwise returns ``(None, error)`` where
    ``error`` names the playbooks the user can pick from — the caller surfaces it and stops.
    """
    classification = Classification.calculate_observable(observable_name)
    # The playbooks that WOULD qualify for this observable: visible, enabled, applicable. Both the
    # default lookup and the fallback list derive from this single queryset so the error names
    # exactly the playbooks that could have run.
    applicable_playbooks = PlaybookConfig.objects.visible_for_user(user).filter(
        disabled=False, type__contains=[classification]
    )
    default_playbook = applicable_playbooks.filter(name=FREE_TO_USE_PLAYBOOK).first()
    if default_playbook is not None:
        reason = (
            f"No playbook or analyzers were specified, so IntelOwl's curated "
            f"'{FREE_TO_USE_PLAYBOOK}' playbook (key-free plugins) was selected for this "
            f"{classification} observable."
        )
        return default_playbook.name, reason

    names = list(applicable_playbooks.order_by("name").values_list("name", flat=True))
    if not names:
        return None, (
            f"No playbook or analyzers were specified and no playbook is available to you for "
            f"{classification} observables; specify analyzers explicitly."
        )
    shown = ", ".join(names[:_MAX_PLAYBOOKS_IN_ERROR])
    if len(names) > _MAX_PLAYBOOKS_IN_ERROR:
        shown += f" (and {len(names) - _MAX_PLAYBOOKS_IN_ERROR} more)"
    return None, (
        f"No playbook or analyzers were specified. Pick one of the playbooks available to you "
        f"for {classification} observables: {shown}."
    )


def _build_analysis_request(
    user, observable_name: str, playbook: str, analyzers: str, tlp: str
) -> tuple[dict | None, str | None, str | None]:
    """Assemble the ``ObservableAnalysisSerializer`` input for the preview, applying the tenancy guards.

    Extracted from the tool closure so the closure stays under the cyclomatic-complexity gate and the
    request assembly is testable on its own. Scoped to ``user`` via ``visible_for_user``, so it adds no
    tenancy boundary. Returns ``(data, plan_reason, error)``:

    - ``(data, reason, None)`` -- feed ``data`` to the serializer. ``reason`` is non-null only when the
      request defaulted to the curated playbook (so the model can explain the choice), else ``None``.
    - ``(None, None, error)`` -- a guard rejected the request; the caller surfaces ``error`` and stops.
    """
    if playbook and not PlaybookConfig.objects.visible_for_user(user).filter(name=playbook).exists():
        # ISOLATION GUARD: ObservableAnalysisSerializer resolves playbook_requested via
        # PlaybookConfig.objects.all() with no visibility filter; scope it here first so another org's
        # private playbook can't leak into the plan.
        return None, None, f"Playbook '{playbook}' not found or not visible to you."

    data = {"observable_name": observable_name, "tlp": tlp}
    if playbook:
        data["playbook_requested"] = playbook
    analyzers_list = [a.strip() for a in analyzers.split(",") if a.strip()]
    if analyzers_list:
        data["analyzers_requested"] = analyzers_list
    if playbook or analyzers_list:
        return data, None, None

    # Neither a playbook nor analyzers were named -- the natural shape of "analyze X". Without a default
    # this validates to zero plugins and the core raises "No Analyzers and Connectors can be run after
    # filtering", which the model paraphrases into "no analyzers available" and the user reads as a
    # broken deploy. Default to the curated FREE_TO_USE_ANALYZERS playbook, or surface an actionable
    # error naming the playbooks the user can pick from.
    resolved_playbook, note = _resolve_default_playbook(user, observable_name)
    if resolved_playbook is None:
        return None, None, note
    data["playbook_requested"] = resolved_playbook
    return data, note, None


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
        data, plan_reason, error = _build_analysis_request(user, observable_name, playbook, analyzers, tlp)
        if error is not None:
            return AnalyzeObservableResultSerializer(
                {"errors": [error], "plan": None, "pending_id": None}
            ).to_json()

        serializer = ObservableAnalysisSerializer(data=data, context={"request": SimpleNamespace(user=user)})
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
            # Non-null only when the plan defaulted to FREE_TO_USE_ANALYZERS, so the model can tell
            # the user WHY that playbook was chosen instead of silently picking one.
            "reason": plan_reason,
        }
        # Store the inputs re-validated at confirm time; the model cannot launch -- only a user POST of
        # this pending_id can. Persist the RESOLVED playbook (may be the defaulted FREE_TO_USE_ANALYZERS)
        # so the confirm endpoint re-validates and launches exactly the previewed plan.
        pending_id = create_pending_analysis(
            user.id,
            {
                "observable_name": observable_name,
                "tlp": tlp,
                "playbook": data.get("playbook_requested", ""),
                "analyzers": analyzers,
            },
        )
        return AnalyzeObservableResultSerializer(
            {"errors": [], "plan": plan, "pending_id": pending_id}
        ).to_json()

    return analyze_observable
