# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from langchain_core.tools import tool

from api_app.choices import ReportStatus


def make_summarize_job_tool(user):
    # Built per-request and closed over `user`: the lookup is scoped with visible_for_user
    # (owner + same-org AMBER/RED + globally-visible CLEAR/GREEN), matching the REST
    # JobViewSet / UI (multi-tenancy enforced here). The payload is human-readable prose
    # (meant to be relayed to the user) wrapped in the same envelope as the other tools.
    @tool("summarize_job")
    def summarize_job(job_id: int) -> str:
        """Return a concise human-readable summary of an IntelOwl job.

        Args:
            job_id: The numeric ID of the job to summarize.

        Returns:
            JSON string with shape {"errors": [...], "summary": "..." | null}.
        """
        from api_app.chatbot_manager.serializers.job import SummarizeJobResultSerializer
        from api_app.models import Job

        try:
            job = (
                Job.objects.select_related("analyzable")
                .prefetch_related("analyzerreports__config", "analyzers_to_execute")
                .visible_for_user(user)
                .get(pk=job_id)
            )
        except Job.DoesNotExist:
            return SummarizeJobResultSerializer(
                {"errors": [f"Job with ID {job_id} not found or not accessible."], "summary": None}
            ).to_json()

        analyzers = list(job.analyzers_to_execute.values_list("name", flat=True))
        # `analyzerreports.*.status` uses ReportStatus (uppercase), distinct from the
        # job-level Status enum: a report that did not succeed is considered failed here.
        failed_reports = [
            r.config.name for r in job.analyzerreports.all() if r.status != ReportStatus.SUCCESS.value
        ]

        lines = [
            f"Job #{job.pk}",
            f"  Observable : {job.analyzable.name} ({job.analyzable.classification})",
            f"  MD5        : {job.analyzable.md5}",
            f"  Status     : {job.status}",
            f"  TLP        : {job.tlp}",
            f"  Received   : {job.received_request_time}",
            f"  Finished   : {job.finished_analysis_time or 'N/A'}",
            f"  Analyzers  : {', '.join(analyzers) or 'none'}",
        ]
        if job.errors:
            lines.append(f"  Errors     : {'; '.join(job.errors[:3])}")
        if failed_reports:
            lines.append(f"  Failed     : {', '.join(failed_reports)}")

        return SummarizeJobResultSerializer({"errors": [], "summary": "\n".join(lines)}).to_json()

    return summarize_job
