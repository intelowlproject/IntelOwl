from django.db import models


class AnalysisStatusChoices(models.TextChoices):
    STARTED = "started"
    JOBS_RUNNING = "jobs_running"
    JOBS_ENDED = "jobs_ended"
    CONCLUDED = "concluded"
