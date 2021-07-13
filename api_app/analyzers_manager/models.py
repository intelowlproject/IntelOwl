# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import models

from api_app.core.models import AbstractReport


class AnalyzerReport(AbstractReport):
    class Meta:
        unique_together = [("analyzer_name", "job")]

    analyzer_name = models.CharField(max_length=128)
    runtime_configuration = models.JSONField(default=dict, null=True, blank=True)
    job = models.ForeignKey(
        "api_app.Job", related_name="analyzer_reports", on_delete=models.CASCADE
    )

    def __str__(self):
        return f"AnalyzerReport(job:#{self.job_id}, {self.analyzer_name})"
