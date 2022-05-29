# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import models

from api_app.core.models import AbstractReport

class PlaybookReport(AbstractReport):
    job = models.ForeignKey(
        "api_app.Job", related_name="playbook_reports", on_delete=models.CASCADE
    )

    class Meta:
        unique_together = [("name", "job")]
    
    def __str__(self):
        return f"PlaybookReport(job:#{self.job_id}, {self.playbook_name})"

    @property
    def playbook_name(self) -> str:
        return self.name
