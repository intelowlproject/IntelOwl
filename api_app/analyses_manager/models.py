from datetime import datetime
from typing import List

from django.conf import settings
from django.db import models

from api_app.analyses_manager.choices import AnalysisStatusChoices
from api_app.analyses_manager.queryset import AnalysisQuerySet
from api_app.choices import TLP
from api_app.interfaces import OwnershipAbstractModel
from api_app.models import ListCachable


class Analysis(OwnershipAbstractModel, ListCachable):
    name = models.CharField(max_length=100)
    description = models.TextField(default="", blank=True)

    start_time = models.DateTimeField(default=datetime.now)
    end_time = models.DateTimeField(default=None, null=True, blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="analyses",
    )
    status = models.CharField(
        choices=AnalysisStatusChoices.choices,
        max_length=20,
        default=AnalysisStatusChoices.CREATED.value,
    )
    Status = AnalysisStatusChoices

    objects = AnalysisQuerySet.as_manager()

    class Meta:
        verbose_name_plural = "analyses"
        indexes = [models.Index(fields=["start_time"])]

    def __str__(self):
        return (
            f"{self.name}:"
            f" jobs {', '.join([str(job.pk) for job in self.jobs.all()])} "
            f"-> {self.status}"
        )

    def set_correct_status(self, save: bool = True):
        from api_app.models import Job

        # if I have some jobs
        if self.jobs.exists():
            # and at least one is running
            for job in self.jobs.all():
                job: Job
                jobs = job.get_tree(job)
                if jobs.exclude(status__in=Job.Status.final_statuses()).count() > 0:
                    self.status = self.Status.RUNNING.value
                    self.end_time = None
                    break
            # and they are all completed
            else:
                self.status = self.Status.CONCLUDED.value
                self.end_time = (
                    self.jobs.order_by("-finished_analysis_time")
                    .first()
                    .finished_analysis_time
                )
        else:
            self.status = self.Status.CREATED.value
            self.end_time = None
        if save:
            self.save(update_fields=["status", "end_time"])

    @property
    def tags(self) -> List[str]:
        return list(set(self.jobs.values_list("tags__label", flat=True)))

    @property
    def tlp(self) -> TLP:
        return (
            max(
                TLP[tlp_string]
                for tlp_string in self.jobs.values_list("tlp", flat=True)
            )
            if self.jobs.exists()
            else TLP.CLEAR.value
        )

    @property
    def total_jobs(self) -> int:
        return (
            sum(job.get_descendant_count() for job in self.jobs.all())
            + self.jobs.count()
        )
