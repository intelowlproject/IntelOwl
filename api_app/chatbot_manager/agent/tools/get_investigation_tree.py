# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from dataclasses import asdict, dataclass, field
from typing import List, Optional

from langchain_core.tools import tool

from api_app.chatbot_manager.serializers.investigation import InvestigationTreeResultSerializer
from api_app.investigations_manager.models import Investigation

# Bounds for the LLM-facing tree: keep the serialized payload small enough not to blow up
# the prompt regardless of how large an investigation is.
_MAX_DEPTH = 10
_MAX_NODES = 200


@dataclass
class _JobNode:
    """One job in the LLM-facing tree: id, observable, status and its children."""

    id: int
    observable: Optional[str]
    status: str
    children: List["_JobNode"] = field(default_factory=list)


@dataclass
class _InvestigationTree:
    """Compact job tree for an investigation. `truncated` is True when a cap was hit."""

    id: int
    name: str
    status: str
    jobs: List[_JobNode] = field(default_factory=list)
    truncated: bool = False


def _node(job) -> _JobNode:
    return _JobNode(id=job.pk, observable=getattr(job.analyzable, "name", None), status=job.status)


def _build_tree(investigation) -> _InvestigationTree:
    """Assemble a compact job tree for an investigation, avoiding the treebeard N+1.

    A Job is a treebeard ``MP_Node``; walking it with ``get_children()`` recursively would
    fire one query per node. Instead we fetch each root's whole subtree with a single
    ``get_descendants()`` call and rebuild the nesting in Python from treebeard's
    materialized ``path`` (a child's parent path is its own path minus the last step), so
    there are no per-node queries. Depth and node count are capped to bound the payload.
    """
    tree = _InvestigationTree(
        id=investigation.pk,
        name=investigation.name,
        status=investigation.status,
    )
    remaining = _MAX_NODES

    # `investigation.jobs` are the root jobs; their descendants live only in the tree.
    for root in investigation.jobs.select_related("analyzable"):
        if remaining <= 0:
            tree.truncated = True
            break
        root_node = _node(root)
        tree.jobs.append(root_node)
        remaining -= 1
        # Index path -> node for every kept node, to link children to parents in O(1).
        by_path = {root.path: root_node}

        # One query for the whole subtree, in path order (treebeard pre-order DFS), so a
        # parent is always processed before its children.
        for job in root.get_descendants().select_related("analyzable").order_by("path"):
            if (job.depth - root.depth) > _MAX_DEPTH:
                continue
            parent = by_path.get(job.path[: -job.steplen])
            if parent is None:
                # Ancestor was capped out (depth/budget); skip to avoid orphaning.
                continue
            if remaining <= 0:
                tree.truncated = True
                break
            node = _node(job)
            by_path[job.path] = node
            parent.children.append(node)
            remaining -= 1

    return tree


def make_get_investigation_tree_tool(user):
    # Built per-request and closed over `user`. The lookup is scoped with
    # `visible_for_user` (owned + organization-shared investigations), so the LLM cannot
    # reach an investigation the user can't see. Returns a string (the tool-call
    # observation): a JSON-serialized envelope.
    @tool("get_investigation_tree")
    def get_investigation_tree(investigation_id: int) -> str:
        """Get the job tree of an IntelOwl investigation by its numeric ID.

        Returns the investigation with its jobs as a nested tree (each node: id,
        observable, status, children). Depth and node count are capped for large trees
        (the `truncated` flag is set to true when the cap is hit).

        Args:
            investigation_id: The numeric ID of the investigation.

        Returns:
            JSON string with shape {"errors": [...], "investigation": {...} | null}.
        """
        try:
            investigation = Investigation.objects.visible_for_user(user).get(pk=investigation_id)
        except Investigation.DoesNotExist:
            return InvestigationTreeResultSerializer(
                {
                    "errors": [f"Investigation with ID {investigation_id} not found or not accessible."],
                    "investigation": None,
                }
            ).to_json()

        return InvestigationTreeResultSerializer(
            {"errors": [], "investigation": asdict(_build_tree(investigation))}
        ).to_json()

    return get_investigation_tree
