from collections import deque

from celery.signals import before_task_publish

from intel_owl.celery import app

task_queue = deque()


@before_task_publish.connect(sender="run_analyzer")
def before_task_publish_handler(headers=None, body=None, **kwargs):
    """
    Used to intercept job creation requests
    """
    task_queue.append(body[1])
    info = headers if "task" in headers else body

    app.control.revoke(info["id"])


print("Celery tester is running")
