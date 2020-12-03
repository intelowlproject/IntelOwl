from __future__ import absolute_import, unicode_literals
from intel_owl.settings import CELERY_QUEUES
import os

from celery import Celery
from celery.schedules import crontab
from kombu import Exchange, Queue

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "intel_owl.settings")

app = Celery("intel_owl")

app.config_from_object("django.conf:settings", namespace="CELERY")
app.conf.update(task_time_limit=1800)  # half hour

app.autodiscover_tasks()

app.conf.task_default_queue = "default"

app.conf.task_queues = [
    Queue(
        key,
        Exchange(key),
        routing_key=key,
    )
    for key in CELERY_QUEUES
]

app.conf.beat_schedule = {
    # execute daily at midnight to cleanup orphaned obj permissions
    "clean_orphan_obj_perms": {
        "task": "intel_owl.tasks.clean_orphan_obj_perms",
        "schedule": crontab(minute=0, hour=0),
        "options": {"queue": "default"},
    },
    # execute sometimes to cleanup old jobs
    "remove_old_jobs": {
        "task": "intel_owl.tasks.remove_old_jobs",
        "schedule": crontab(minute=10, hour=2),
        "options": {"queue": "default"},
    },
    # execute sometimes to cleanup stuck analysis
    "check_stuck_analysis": {
        "task": "intel_owl.tasks.check_stuck_analysis",
        "schedule": crontab(minute="*/5"),
        "options": {"queue": "default"},
    },
    # Executes only on Wed because on Tue it's updated
    "maxmind_updater": {
        "task": "intel_owl.tasks.maxmind_updater",
        "schedule": crontab(minute=0, hour=1, day_of_week=3),
        "options": {"queue": "default"},
    },
    # execute every 6 hours
    "talos_updater": {
        "task": "intel_owl.tasks.talos_updater",
        "schedule": crontab(minute=5, hour="*/6"),
        "options": {"queue": "default"},
    },
    # execute every 10 minutes
    "tor_updater": {
        "task": "intel_owl.tasks.tor_updater",
        "schedule": crontab(minute="*/10"),
        "options": {"queue": "default"},
    },
    # yara repo updater 1 time a day
    "yara_updater": {
        "task": "intel_owl.tasks.yara_updater",
        "schedule": crontab(minute=0, hour=0),
        "options": {"queue": "default"},
    },
}
