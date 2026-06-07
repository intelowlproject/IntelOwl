# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from langchain_core.tools import tool

from api_app.chatbot_manager.agent.tools._common import clamp_limit
from api_app.chatbot_manager.serializers import RecommendPlaybookResultSerializer
from api_app.choices import Classification
from api_app.playbooks_manager.models import PlaybookConfig


def make_recommend_playbook_tool(user):
    # Built per-request and closed over `user`. Playbooks are owned / org-shared objects (unlike
    # the global analyzer configs), so the queryset is scoped with `visible_for_user`, which
    # returns the playbooks the user owns, the ones shared with their organization and the global
    # ones (owner is null). This is a real visibility boundary -- another org's private playbook
    # must not leak -- and the LLM can never widen it.
    @tool("recommend_playbook")
    def recommend_playbook(observable_name: str = "", classification: str = "", limit: int = 10) -> str:
        """Suggest IntelOwl playbooks that can analyze a given observable.

        Returns the directly-launchable playbooks (those that can start an analysis on their own)
        applicable to the observable's classification and visible to you.

        Args:
            observable_name: The observable (IP, domain, URL, hash, ...). When `classification`
                    is not given, the classification is derived from this value.
            classification: The observable classification to match playbooks against. Valid
                    values: ip, url, domain, hash, generic, file. If omitted it is derived from
                    `observable_name`; an unknown explicit value is reported in `errors`.
            limit: Maximum number of results to return (default 10, max 50).

        Returns:
            JSON string with shape {"errors": [...], "playbooks": [...]}.
        """
        errors = []

        if not observable_name.strip() and not classification.strip():
            errors.append("Provide either an observable_name or a classification.")
            return RecommendPlaybookResultSerializer({"errors": errors, "playbooks": []}).to_json()

        if classification:
            # Explicit classification comes from the LLM; validate it against the enum so an
            # invalid value surfaces a message instead of silently returning 0 results.
            classification = classification.strip().lower()
            if classification not in set(Classification.values):
                valid = ", ".join(Classification.values)
                errors.append(f"Unknown classification '{classification}'; valid values are: {valid}.")
                return RecommendPlaybookResultSerializer({"errors": errors, "playbooks": []}).to_json()
        else:
            # Reuse the same classification logic the real analysis pipeline uses, so the
            # recommendation matches what an actual scan would pick.
            classification = Classification.calculate_observable(observable_name)

        # Treat the LLM-supplied limit as untrusted: clamp it (so a broadly-supported
        # classification can't flood the prompt) and surface any capping in `errors`.
        limit = clamp_limit(limit, errors)
        # `type` is a ChoiceArrayField of classifications: `__contains` matches playbooks declaring
        # support for this one. `starting=True` = launchable on its own (not pivot-only).
        # `prefetch_related` avoids the per-row N+1 from the analyzers/connectors SlugRelatedFields.
        qs = (
            PlaybookConfig.objects.filter(type__contains=[classification], starting=True, disabled=False)
            .visible_for_user(user)
            .prefetch_related("analyzers", "connectors")
            .order_by("name")[:limit]
        )

        return RecommendPlaybookResultSerializer({"errors": errors, "playbooks": qs}).to_json()

    return recommend_playbook
