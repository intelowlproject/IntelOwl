from collections import deque

from celery.signals import before_task_publish

from intel_owl.celery import app

task_queue = deque()


@before_task_publish.connect(sender="job_pipeline")
def before_task_publish_handler(headers=None, body=None, **kwargs):
    """
    Used to intercept job creation requests
    """
    kwargs = body[1]
    task_queue.append(kwargs)
    info = headers if "task" in headers else body

    app.control.revoke(info["id"])


print("Celery tester is running")
