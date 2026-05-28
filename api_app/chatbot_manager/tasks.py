# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from celery import shared_task

from intel_owl.tasks import FailureLoggedTask


@shared_task(base=FailureLoggedTask, soft_time_limit=300)
def process_chat_message(session_id: int, user_message: str, user_id: int) -> str:
    # Stub — full async implementation added in W6 with WebSocket consumer.
    raise NotImplementedError
