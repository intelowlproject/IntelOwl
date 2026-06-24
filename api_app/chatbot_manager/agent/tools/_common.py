# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Helpers shared by the chatbot agent tools (this module is not itself a tool)."""

# Hard cap on the number of results any single tool returns to the LLM, so one call can't pull
# an unbounded list into the prompt. Shared here so every tool advertises the same ceiling.
MAX_RESULTS = 50


def clamp_limit(limit, errors: list) -> int:
    """Clamp an LLM-supplied result limit into ``[1, MAX_RESULTS]``.

    Tool arguments are untrusted, so the raw ``limit`` is coerced to ``int`` and bounded. When
    the requested value is above the cap, a note is appended to ``errors`` so a truncated list is
    never silent (the lower bound is enforced too, but a non-positive request is not worth a
    warning). Returns the clamped limit.
    """
    requested_limit = int(limit)
    if requested_limit > MAX_RESULTS:
        errors.append(
            f"Requested limit {requested_limit} exceeds the maximum {MAX_RESULTS}; "
            f"returning at most {MAX_RESULTS} results."
        )
    return max(1, min(requested_limit, MAX_RESULTS))


def on_invalid_tool_args(error: Exception) -> str:
    """Observation returned when an LLM tool call fails the tool's argument schema.

    Set as ``handle_validation_error`` on every built tool (see ``build_tools``). The pydantic
    ``ValidationError`` is raised in ``BaseTool._parse_input`` *before* the tool body runs, so it is
    not covered by ``AgentExecutor(handle_parsing_errors=...)`` (which only feeds back the model's
    unparseable *output*). Returning the error as an observation -- instead of letting it propagate
    and kill the whole turn as ``UNAVAILABLE`` -- lets the agent retry with the real value; if it
    keeps emitting a bad value the run force-stops at ``max_iterations`` rather than crashing. The
    message surfaces the failure and steers the model to substitute the actual value from a previous
    tool result, not a placeholder.
    """
    return (
        f"Invalid tool arguments: {error}. "
        "Use the actual value from a previous tool result (for example a numeric id), "
        "not a placeholder such as '<job_id>'. Then call the tool again."
    )
