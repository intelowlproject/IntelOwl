from __future__ import absolute_import, unicode_literals

import os

from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "intel_owl.settings")

app = Celery("intel_owl")

app.config_from_object("django.conf:settings", namespace="CELERY")

app.autodiscover_tasks()

app.conf.beat_schedule = {
    # execute sometimes to cleanup old jobs
    "remove_old_jobs": {
        "task": "intel_owl.tasks.remove_old_jobs",
        "schedule": crontab(minute=10, hour=2),
    },
    # execute sometimes to cleanup stuck analysis
    "check_stuck_analysis": {
        "task": "intel_owl.tasks.check_stuck_analysis",
        "schedule": crontab(minute="*/5"),
    },
    # execute every 6 hours to cleanup expired tokens
    "flush_expired_tokens": {
        "task": "intel_owl.tasks.flush_expired_tokens",
        "schedule": crontab(hour="*/6"),
    },
    # Executes only on Wed because on Tue it's updated
    "maxmind_updater": {
        "task": "intel_owl.tasks.maxmind_updater",
        "schedule": crontab(minute=0, hour=1, day_of_week=3),
    },
    # execute every 6 hours
    "talos_updater": {
        "task": "intel_owl.tasks.talos_updater",
        "schedule": crontab(minute=5, hour="*/6"),
    },
    # execute every 10 minutes
    "tor_updater": {
        "task": "intel_owl.tasks.tor_updater",
        "schedule": crontab(minute="*/10"),
    },
    # yara repo updater 1 time a day
    "yara_updater": {
        "task": "intel_owl.tasks.yara_updater",
        "schedule": crontab(minute=0, hour=0),
    },
}
