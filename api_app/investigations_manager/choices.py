from django.db import models


class InvestigationStatusChoices(models.TextChoices):
    CREATED = "created"
    RUNNING = "running"
    CONCLUDED = "concluded"
