# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import models

from api_app.core.models import AbstractReport


class VisualizerReport(AbstractReport):
    job = models.ForeignKey(
        "api_app.Job", related_name="visualizer_reports", on_delete=models.CASCADE
    )

    class Meta:
        unique_together = [("name", "job")]

    @property
    def visualizer_name(self) -> str:
        return self.name
