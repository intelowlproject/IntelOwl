# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from .analyze_observable import make_analyze_observable_tool
from .get_data_model import make_get_data_model_tool
from .get_investigation_tree import make_get_investigation_tree_tool
from .get_job_details import make_get_job_details_tool
from .list_analyzers import make_list_analyzers_tool
from .list_investigations import make_list_investigations_tool
from .recommend_playbook import make_recommend_playbook_tool
from .search_jobs import make_search_jobs_tool
from .summarize_investigation import make_summarize_investigation_tool
from .summarize_job import make_summarize_job_tool


def build_tools(user) -> list:
    """Build the agent's tools bound to a single user.

    Each tool is produced by a factory that closes over `user`, so every ORM query the
    agent can run is hard-scoped to that user's data: multi-tenancy is enforced at build
    time and cannot be widened by anything the LLM emits. Job, investigation, and playbook
    tools scope on `visible_for_user` (owner + same-org AMBER/RED + globally-visible
    CLEAR/GREEN), matching the REST viewsets / UI. Analyzer configs are global plugin
    definitions, so `list_analyzers` does not scope by owner -- it lists the enabled
    analyzers and exposes per-user readiness through a `runnable` flag instead. The single
    action tool `analyze_observable` can launch a real analysis; it is confirm-gated (a preview
    unless `confirm=True`) and creates jobs owned by `user`. Every tool returns a string
    (LangChain feeds it back to the model as the tool-call observation); see each tool
    for its shape.
    """
    return [
        make_search_jobs_tool(user),
        make_get_job_details_tool(user),
        make_summarize_job_tool(user),
        make_list_investigations_tool(user),
        make_get_investigation_tree_tool(user),
        make_summarize_investigation_tool(user),
        make_get_data_model_tool(user),
        make_list_analyzers_tool(user),
        make_recommend_playbook_tool(user),
        make_analyze_observable_tool(user),
    ]
