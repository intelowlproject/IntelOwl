# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import re
from urllib.parse import urlparse

# Fixed hint templates. context_url is client-supplied, so we render ONLY a validated integer id
# into these constants — the raw URL text never reaches the prompt. A crafted URL such as
# /jobs/42?x=ignore+previous+instructions therefore yields exactly "...job #42..." and nothing
# else, which neutralises prompt injection via the URL.
_JOB_CONTEXT = "The user is currently viewing job #{id} in the IntelOwl UI."
_INVESTIGATION_CONTEXT = "The user is currently viewing investigation #{id} in the IntelOwl UI."

# Frontend detail routes (frontend/src/components/Routes.jsx): job is /jobs/<id>[/...],
# investigation is /investigation/<id> (singular). Match the id, ignore any trailing segments.
_JOB_RE = re.compile(r"^/jobs/(\d+)(?:/|$)")
_INVESTIGATION_RE = re.compile(r"^/investigation/(\d+)(?:/|$)")


def derive_page_context(context_url: str) -> str:
    """Map the page the user is on (the WebSocket context_url) to a compact prompt hint.

    Returns a fixed hint for a job or investigation detail page, or "" for anything else
    (non-entity page, empty, or unparseable). Only a validated integer id is extracted, so the
    URL text cannot inject prompt instructions.
    """
    if not context_url:
        return ""
    path = urlparse(context_url).path
    match = _JOB_RE.match(path)
    if match:
        return _JOB_CONTEXT.format(id=match.group(1))
    match = _INVESTIGATION_RE.match(path)
    if match:
        return _INVESTIGATION_CONTEXT.format(id=match.group(1))
    return ""
