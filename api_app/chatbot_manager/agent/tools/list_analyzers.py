# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from langchain_core.tools import tool

from api_app.analyzers_manager.constants import TypeChoices
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.chatbot_manager.agent.tools._common import clamp_limit
from api_app.chatbot_manager.serializers import ListAnalyzersResultSerializer
from api_app.choices import Classification


def make_list_analyzers_tool(user):
    # Built per-request and closed over `user`. Unlike the job/investigation tools, analyzer
    # configs are GLOBAL plugin definitions (not user-owned), so the queryset is not scoped to
    # the user's own rows; it lists the enabled observable analyzers and exposes per-user
    # readiness through the `runnable` annotation instead.
    #
    # Why no `.filter(runnable=True)`: `annotate_runnable` (queryset.py) folds health-check +
    # "all required parameters configured" on top of enabled/org-enabled, so a hard filter would
    # silently drop every key-based analyzer (VirusTotal, ...) on a deploy without API keys ->
    # near-empty lists and flaky tests. We list the enabled analyzers and surface readiness as a
    # per-row flag instead, so the LLM can still say "this analyzer applies but isn't configured
    # for you". `runnable` is False when the analyzer is disabled for the user's organization OR
    # not fully configured/healthy.
    @tool("list_analyzers")
    def list_analyzers(observable_type: str = "", limit: int = 10) -> str:
        """List the observable analyzers enabled on this IntelOwl instance.

        Each result carries a `runnable` flag: True means the analyzer is ready to run for you
        (enabled for your organization and fully configured); False means it applies but is
        currently disabled for your organization or missing required configuration (e.g. an API
        key).

        Args:
            observable_type: Filter to analyzers supporting this observable type. Valid values:
                    ip, url, domain, hash, generic. An unknown value is ignored and reported in
                    `errors`.
            limit: Maximum number of results to return (default 10, max 50).

        Returns:
            JSON string with shape {"errors": [...], "analyzers": [...]}.
        """
        errors = []
        # Globally-enabled observable analyzers, annotated with per-user readiness. Org-disabled
        # or unconfigured analyzers still appear, flagged `runnable=False`.
        qs = AnalyzerConfig.objects.filter(type=TypeChoices.OBSERVABLE, disabled=False).annotate_runnable(
            user
        )

        # The accepted observable types are an IntelOwl-core notion (every classification except
        # FILE, which is the file-analysis path), so reuse the core helper instead of a local copy.
        valid_types = Classification.observable_classifications()
        if observable_type:
            # The type string comes from the LLM; validate it against the enum so an invalid
            # value surfaces a message instead of silently returning 0 results.
            normalized = observable_type.strip().lower()
            if normalized in set(valid_types):
                # `observable_supported` is a ChoiceArrayField: `__contains` matches rows whose
                # array includes the requested type.
                qs = qs.filter(observable_supported__contains=[normalized])
            else:
                valid = ", ".join(valid_types)
                errors.append(f"Unknown observable_type '{observable_type}'; valid values are: {valid}.")

        # Treat the LLM-supplied limit as untrusted: clamp it and surface any capping in `errors`.
        limit = clamp_limit(limit, errors)
        qs = qs.order_by("name")[:limit]

        return ListAnalyzersResultSerializer({"errors": errors, "analyzers": qs}).to_json()

    return list_analyzers
