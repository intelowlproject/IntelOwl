from django.db import models


class AnalysisStatusChoices(models.TextChoices):
    CREATED = "created"
    RUNNING = "running"
    CONCLUDED = "concluded"
