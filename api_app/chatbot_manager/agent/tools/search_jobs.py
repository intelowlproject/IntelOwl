# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json

from django.db import models
from langchain_core.tools import tool


def make_search_jobs_tool(user):
    @tool("search_jobs")
    def search_jobs(query: str = "", status: str = "", limit: int = 10) -> str:
        """Search IntelOwl jobs by observable name, MD5, or status.

        Args:
            query: Observable name or MD5 hash to search for (partial match supported).
            status: Filter by job status. Valid values: pending, running,
                    reported_without_fails, reported_with_fails, failed, killed.
            limit: Maximum number of results to return (default 10, max 50).
        """
        from api_app.models import Job

        limit = min(int(limit), 50)
        qs = Job.objects.select_related("analyzable").filter(user=user)

        if query:
            qs = qs.filter(
                models.Q(analyzable__name__icontains=query) | models.Q(analyzable__md5__iexact=query)
            )
        if status:
            qs = qs.filter(status=status)

        qs = qs.order_by("-received_request_time")[:limit]

        results = []
        for job in qs:
            results.append(
                {
                    "id": job.pk,
                    "observable_name": job.analyzable.name,
                    "observable_classification": job.analyzable.classification,
                    "md5": job.analyzable.md5,
                    "status": job.status,
                    "tlp": job.tlp,
                    "received_request_time": str(job.received_request_time),
                    "finished_analysis_time": str(job.finished_analysis_time)
                    if job.finished_analysis_time
                    else None,
                    "analyzers_to_execute": list(job.analyzers_to_execute.values_list("name", flat=True)),
                }
            )

        if not results:
            return "No jobs found matching the given criteria."
        return json.dumps(results, indent=2)

    return search_jobs
