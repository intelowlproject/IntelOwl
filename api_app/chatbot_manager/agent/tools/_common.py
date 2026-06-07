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
