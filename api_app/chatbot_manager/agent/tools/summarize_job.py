# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from langchain_core.tools import tool

from api_app.chatbot_manager.evaluation import evaluate_job
from api_app.chatbot_manager.serializers.job import SummarizeJobResultSerializer
from api_app.choices import ReportStatus
from api_app.models import Job


def make_summarize_job_tool(user):
    # Built per-request and closed over `user`: the lookup is scoped with visible_for_user
    # (owner + same-org AMBER/RED + globally-visible CLEAR/GREEN), matching the REST
    # JobViewSet / UI (multi-tenancy enforced here). The payload pairs human-readable prose
    # (meant to be relayed to the user) with the structured verdict, in the same envelope as
    # the other tools.
    @tool("summarize_job")
    def summarize_job(job_id: int) -> str:
        """Summarize an IntelOwl job AND report IntelOwl's verdict on the observable.

        The verdict says whether the observable is malicious, suspicious, clean, trusted, or has
        no evaluation, and lists the analyzers supporting or contradicting it. It is IntelOwl's
        own reconciled evaluation — the same one shown on the job page — not an opinion of yours.

        Args:
            job_id: The numeric ID of the job to summarize.

        Returns:
            JSON string with shape
            {"errors": [...], "summary": "..." | null, "verdict": {...} | null}, where `verdict`
            carries `headline` (relay it as-is), `bucket`, `reliability`, `supporting`,
            `contradicting` and the analyzers that had no opinion.
        """
        try:
            job = (
                Job.objects.select_related("analyzable")
                .prefetch_related("analyzerreports__config", "analyzers_to_execute")
                .visible_for_user(user)
                .get(pk=job_id)
            )
        except Job.DoesNotExist:
            return SummarizeJobResultSerializer(
                {
                    "errors": [f"Job with ID {job_id} not found or not accessible."],
                    "summary": None,
                    "verdict": None,
                }
            ).to_json()

        analyzers = list(job.analyzers_to_execute.values_list("name", flat=True))
        # `analyzerreports.*.status` uses ReportStatus (uppercase), distinct from the
        # job-level Status enum: a report that did not succeed is considered failed here.
        failed_reports = [
            r.config.name for r in job.analyzerreports.all() if r.status != ReportStatus.SUCCESS.value
        ]

        verdict = evaluate_job(job)
        lines = [
            f"Job #{job.pk}",
            # The headline is duplicated here on purpose. It is also carried structurally in
            # `verdict`, but a live smoke against qwen2.5:3b showed the model reproduces the prose
            # fields of this summary verbatim while paraphrasing the structured object — dropping
            # the reliability and confusing contradicting analyzers with silent ones. Stating the
            # copy-ready sentence in the prose is what makes the narration match the badge.
            f"  Verdict    : {verdict.headline}",
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

        # The verdict is ALSO kept structured, so the model can relay exact analyzer names and
        # numbers instead of paraphrasing them; only the headline is echoed into the prose above.
        return SummarizeJobResultSerializer(
            {"errors": [], "summary": "\n".join(lines), "verdict": verdict}
        ).to_json()

    return summarize_job
