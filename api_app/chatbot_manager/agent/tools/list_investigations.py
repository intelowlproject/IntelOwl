# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from langchain_core.tools import tool

from api_app.chatbot_manager.agent.tools._common import clamp_limit
from api_app.chatbot_manager.serializers.investigation import InvestigationsResultSerializer
from api_app.investigations_manager.choices import InvestigationStatusChoices
from api_app.investigations_manager.models import Investigation


def make_list_investigations_tool(user):
    # Built per-request and closed over `user`: the queryset is scoped with
    # `visible_for_user`, which returns the investigations the user owns AND those shared
    # with their organization (`for_organization=True`). This is wider than the job tools'
    # `user=user` scope on purpose -- investigations have an explicit org-sharing flag --
    # and the LLM can never widen it. LangChain feeds a tool's return value back as the
    # tool-call observation, so it must be a string: we return a JSON-serialized envelope.
    @tool("list_investigations")
    def list_investigations(query: str = "", status: str = "", limit: int = 10) -> str:
        """List IntelOwl investigations visible to you (owned or shared with your org).

        Args:
            query: Filter by investigation name (case-insensitive partial match).
            status: Filter by investigation status. Valid values: created, running,
                    concluded. An unknown value is ignored and reported in `errors`.
            limit: Maximum number of results to return (default 10, max 50).

        Returns:
            JSON string with shape {"errors": [...], "investigations": [...]}.
        """
        errors = []
        qs = Investigation.objects.visible_for_user(user)

        if query:
            qs = qs.filter(name__icontains=query)
        if status:
            # The status string comes from the LLM; validate it against the enum so an
            # invalid value surfaces a message instead of silently returning 0 results.
            normalized = status.strip().lower()
            if normalized in set(InvestigationStatusChoices.values):
                qs = qs.filter(status=normalized)
            else:
                valid = ", ".join(InvestigationStatusChoices.values)
                errors.append(f"Unknown status '{status}'; valid values are: {valid}.")

        limit = clamp_limit(limit, errors)
        qs = qs.order_by("-start_time")[:limit]

        return InvestigationsResultSerializer({"errors": errors, "investigations": qs}).to_json()

    return list_investigations
