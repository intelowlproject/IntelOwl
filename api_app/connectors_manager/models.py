# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import models

from api_app.core.models import AbstractReport


class ConnectorReport(AbstractReport):
    class Meta:
        unique_together = [("connector", "job")]

    connector = models.CharField(max_length=128)
    job = models.ForeignKey(
        "api_app.Job", related_name="connector_reports", on_delete=models.CASCADE
    )

    def __str__(self):
        return f"ConnectorReport(job:#{self.job_id}, {self.connector})"
