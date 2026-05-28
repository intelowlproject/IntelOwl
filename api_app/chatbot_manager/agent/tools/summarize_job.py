# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


def make_summarize_job_tool(user):
    from langchain_core.tools import tool

    @tool("summarize_job")
    def summarize_job(job_id: int) -> str:
        """Return a concise human-readable summary of an IntelOwl job.

        Args:
            job_id: The numeric ID of the job to summarize.
        """
        from api_app.models import Job

        try:
            job = (
                Job.objects.select_related("analyzable")
                .prefetch_related("analyzer_reports", "analyzers_to_execute")
                .get(pk=job_id, user=user)
            )
        except Job.DoesNotExist:
            return f"Job with ID {job_id} not found or not accessible."

        analyzers = list(job.analyzers_to_execute.values_list("name", flat=True))
        failed_reports = [
            r.config.name
            for r in job.analyzer_reports.all()
            if r.status not in ("success", "reported_without_fails")
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

        return "\n".join(lines)

    return summarize_job
