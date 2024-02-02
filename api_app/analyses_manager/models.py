from datetime import datetime

from django.conf import settings
from django.db import models

from api_app.analyses_manager.choices import AnalysisStatusChoices
from api_app.interfaces import OwnershipAbstractModel


class Analysis(OwnershipAbstractModel):
    name = models.CharField(max_length=100)
    description = models.TextField(default="", blank=True)

    start_time = models.DateTimeField(default=datetime.now)
    end_time = models.DateTimeField(default=None, null=True, blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="analyses",
    )
    status = models.CharField(
        choices=AnalysisStatusChoices.choices,
        max_length=20,
        default=AnalysisStatusChoices.STARTED.value,
    )
    Status = AnalysisStatusChoices

    class Meta:
        verbose_name_plural = "analyses"

    def __str__(self):
        return (
            f"{self.name}:"
            f" jobs {', '.join([str(job.pk) for job in self.jobs.all()])} "
            f"-> {self.status}"
        )

    def conclude(self):
        self.status = self.Status.CONCLUDED.value
        self.end_time = datetime.now()
        self.save()
