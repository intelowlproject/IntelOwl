# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import models
from langchain_core.tools import tool

from api_app.chatbot_manager.agent.tools._common import clamp_limit
from api_app.choices import Status


def make_search_jobs_tool(user):
    # The tool is built per-request and closes over `user`: every query is hard-scoped
    # to that user's jobs, so multi-tenancy is enforced here and the LLM can never widen
    # it. LangChain feeds a tool's return value back to the model as the tool-call
    # observation, so it must be a string; we return a JSON-serialized envelope.
    @tool("search_jobs")
    def search_jobs(query: str = "", status: str = "", limit: int = 10) -> str:
        """Search IntelOwl jobs by observable name, MD5, or status.

        Args:
            query: Observable name or MD5 hash to search for (partial match supported).
            status: Filter by job status (see api_app.choices.Status for valid values).
                    An unknown value is ignored and reported in `errors`.
            limit: Maximum number of results to return (default 10, max 50).

        Returns:
            JSON string with shape {"errors": [...], "jobs": [...]}.
        """
        from api_app.chatbot_manager.serializers.job import SearchJobsResultSerializer
        from api_app.models import Job

        errors = []
        limit = clamp_limit(limit, errors)
        qs = (
            Job.objects.select_related("analyzable")
            .prefetch_related("analyzers_to_execute")
            .filter(user=user)
        )

        if query:
            qs = qs.filter(
                models.Q(analyzable__name__icontains=query) | models.Q(analyzable__md5__iexact=query)
            )
        if status:
            # The status string comes from the LLM; validate it against the enum so an
            # invalid value surfaces a message instead of silently returning 0 results
            # (mirrors list_investigations).
            normalized = status.strip().lower()
            if normalized in set(Status.values):
                qs = qs.filter(status=normalized)
            else:
                valid = ", ".join(Status.values)
                errors.append(f"Unknown status '{status}'; valid values are: {valid}.")

        qs = qs.order_by("-received_request_time")[:limit]

        return SearchJobsResultSerializer({"errors": errors, "jobs": qs}).to_json()

    return search_jobs
