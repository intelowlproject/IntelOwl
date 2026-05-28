# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from .get_job_details import make_get_job_details_tool
from .search_jobs import make_search_jobs_tool
from .summarize_job import make_summarize_job_tool


def build_tools(user) -> list:
    return [
        make_search_jobs_tool(user),
        make_get_job_details_tool(user),
        make_summarize_job_tool(user),
    ]
