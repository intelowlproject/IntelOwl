# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from celery import shared_task

from intel_owl.tasks import FailureLoggedTask


# soft_time_limit is 300s on purpose: a single chat turn can chain several ReAct
# iterations, each one an Ollama inference on a local model, so it can legitimately take
# tens of seconds to a couple of minutes. A *soft* limit raises SoftTimeLimitExceeded
# (catchable, lets us clean up) rather than a hard time_limit that SIGKILLs the worker,
# and it bounds a hung Ollama call so it can't occupy a worker indefinitely.
@shared_task(base=FailureLoggedTask, soft_time_limit=300)
def process_chat_message(session_id: int, user_message: str, user_id: int) -> str:
    # TODO: full async implementation via the WebSocket consumer + Celery task.
    raise NotImplementedError
