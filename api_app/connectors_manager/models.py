# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import models

from api_app.core.models import AbstractReport


class ConnectorReport(AbstractReport):
    job = models.ForeignKey(
        "api_app.Job", related_name="connector_reports", on_delete=models.CASCADE
    )

    class Meta:
        unique_together = [("name", "job")]

    def __str__(self):
        return f"ConnectorReport(job:#{self.job_id}, {self.connector_name})"

    @property
    def connector_name(self) -> str:
        return self.name
