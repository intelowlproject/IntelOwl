# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from langchain_core.tools import tool


def make_get_job_details_tool(user):
    # Built per-request and closed over `user`, so the lookup is hard-scoped to that
    # user's jobs (multi-tenancy enforced here). LangChain requires a tool to return a
    # string (the tool-call observation), so we return a JSON-serialized envelope.
    @tool("get_job_details")
    def get_job_details(job_id: int) -> str:
        """Get full details of an IntelOwl job by its numeric ID.

        Args:
            job_id: The numeric ID of the job to retrieve.

        Returns:
            JSON string with shape {"errors": [...], "job": {...} | null}.
        """
        from api_app.chatbot_manager.serializers.job import JobDetailResultSerializer
        from api_app.models import Job

        try:
            job = (
                Job.objects.select_related("analyzable")
                .prefetch_related("analyzerreports__config", "analyzers_to_execute", "tags")
                .get(pk=job_id, user=user)
            )
        except Job.DoesNotExist:
            return JobDetailResultSerializer(
                {"errors": [f"Job with ID {job_id} not found or not accessible."], "job": None}
            ).to_json()

        return JobDetailResultSerializer({"errors": [], "job": job}).to_json()

    return get_job_details
