# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging

import httpx
from django.conf import settings

logger = logging.getLogger(__name__)

MAX_TOOL_RESULT_CHARS = 8000

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "search_jobs",
            "description": (
                "Search IntelOwl analysis jobs. "
                "Returns a list of jobs matching the given filters."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "observable_name": {
                        "type": "string",
                        "description": "Filter by observable value (IP, domain, hash, etc.)",
                    },
                    "status": {
                        "type": "string",
                        "enum": [
                            "pending",
                            "running",
                            "reported_without_fails",
                            "reported_with_fails",
                            "failed",
                        ],
                        "description": "Filter by job status",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results to return (default 10)",
                        "default": 10,
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_job_report",
            "description": (
                "Get the full analysis report for a specific job, "
                "including all analyzer results."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "job_id": {
                        "type": "integer",
                        "description": "The job ID to retrieve",
                    },
                },
                "required": ["job_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_analyzer_config",
            "description": "Get configuration details for a specific analyzer plugin.",
            "parameters": {
                "type": "object",
                "properties": {
                    "analyzer_name": {
                        "type": "string",
                        "description": "Name of the analyzer",
                    },
                },
                "required": ["analyzer_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_observables",
            "description": (
                "Search for previously analyzed observables "
                "(IPs, domains, hashes, URLs)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": "The observable value to search for",
                    },
                    "type": {
                        "type": "string",
                        "enum": ["ip", "domain", "url", "hash", "generic"],
                        "description": "Observable type filter",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_scan",
            "description": (
                "Submit a new observable for analysis. "
                "Only call this when the user explicitly asks to scan something. "
                "Always confirm with the user before calling."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "observable_name": {
                        "type": "string",
                        "description": "The value to analyze (IP, domain, URL, hash)",
                    },
                    "observable_classification": {
                        "type": "string",
                        "enum": ["ip", "domain", "url", "hash", "generic"],
                        "description": "Type of the observable",
                    },
                    "analyzers_requested": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Specific analyzers to run. Empty means use defaults."
                        ),
                    },
                },
                "required": ["observable_name", "observable_classification"],
            },
        },
    },
]


def _truncate(text: str, max_chars: int = MAX_TOOL_RESULT_CHARS) -> str:
    """Truncate text to fit within context window limits."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... (truncated)"


async def execute_tool(
    name: str,
    args: dict,
    auth_token: str,
) -> dict:
    """Dispatch a tool call to the appropriate IntelOwl API endpoint.

    All calls go through IntelOwl's REST API using the requesting user's
    auth token, ensuring permission scoping.
    """
    base_url = getattr(settings, "CHATBOT_INTELOWL_BASE_URL", "http://uwsgi:8001")
    headers = {"Authorization": f"Token {auth_token}"}

    async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
        if name == "search_jobs":
            params = {k: v for k, v in args.items() if v is not None and k != "limit"}
            resp = await client.get("/api/jobs", params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", data) if isinstance(data, dict) else data
            limit = args.get("limit", 10)
            return {"jobs": results[:limit]}

        elif name == "get_job_report":
            resp = await client.get(
                f"/api/jobs/{args['job_id']}", headers=headers
            )
            resp.raise_for_status()
            result = resp.json()
            # Truncate large reports to fit context window.
            result_str = json.dumps(result)
            if len(result_str) > MAX_TOOL_RESULT_CHARS:
                return json.loads(_truncate(json.dumps(result, indent=None)))
            return result

        elif name == "get_analyzer_config":
            resp = await client.get("/api/analyzer", headers=headers)
            resp.raise_for_status()
            configs = resp.json()
            if isinstance(configs, dict):
                configs = configs.get("results", [])
            match = [c for c in configs if c.get("name") == args["analyzer_name"]]
            if match:
                return match[0]
            return {"error": f"Analyzer '{args['analyzer_name']}' not found"}

        elif name == "search_observables":
            params = {k: v for k, v in args.items() if v is not None}
            resp = await client.get("/api/analyzable", params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return {"observables": data.get("results", [])[:20]}

        elif name == "create_scan":
            payload = {
                "observable_name": args["observable_name"],
                "observable_classification": args["observable_classification"],
                "analyzers_requested": args.get("analyzers_requested", []),
            }
            resp = await client.post(
                "/api/analyze_observable", json=payload, headers=headers
            )
            resp.raise_for_status()
            return resp.json()

        else:
            return {"error": f"Unknown tool: {name}"}
