# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import models
from api_app.models import Job

class CachedPlaybook(models.Model):
    name = models.CharField(max_length=225, primary_key=True)
    # Required fields
    description = models.CharField(max_length=225, default="", blank=True)
    analyzers = models.JSONField(default=dict)
    connectors = models.JSONField(default=dict)

    # Optional Fields
    supports = models.JSONField(default=list)
    default = models.BooleanField(default=True)
    job = models.ForeignKey(
        Job,
        on_delete=models.CASCADE,
    )