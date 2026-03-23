import datetime
import logging
from typing import List

from django.conf import settings
from django.db import models
from django.db.models import QuerySet
from django.utils.timezone import now

from api_app.choices import TLP
from api_app.interfaces import OwnershipAbstractModel
from api_app.investigations_manager.choices import InvestigationStatusChoices
from api_app.investigations_manager.queryset import InvestigationQuerySet
from api_app.models import Analyzable, Job, ListCachable
from certego_saas.apps.user.models import User

logger = logging.getLogger(__name__)


class Investigation(OwnershipAbstractModel, ListCachable):
    jobs: QuerySet
    name = models.CharField(max_length=100)
    description = models.TextField(default="", blank=True)

    start_time = models.DateTimeField(default=datetime.datetime.now)
    end_time = models.DateTimeField(default=None, null=True, blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="investigations",
    )
    status = models.CharField(
        choices=InvestigationStatusChoices.choices,
        max_length=20,
        default=InvestigationStatusChoices.CREATED.value,
    )
    STATUSES = InvestigationStatusChoices

    objects = InvestigationQuerySet.as_manager()

    class Meta:
        verbose_name_plural = "investigations"
        indexes = [models.Index(fields=["start_time"])]

    def __str__(self):
        return f"{self.name}: jobs {', '.join([str(job.pk) for job in self.jobs.all()])} -> {self.status}"

    def user_can_edit(self, user: User) -> bool:
        if (
            # same organization if investigation is at org level
            self.for_organization
            and (
                user.has_membership()
                and self.owner.has_membership()
                and user.membership.organization == self.owner.membership.organization
            )
            # or same user
        ) or user == self.owner:
            return True
        return False

    def set_correct_status(self, save: bool = True):
        logger.info(f"Setting status for investigation {self.pk}")
        # if I have some jobs
        if self.jobs.exists():
            # and at least one is running
            for job in self.jobs.all():
                job: Job
                jobs = job.get_tree(job)
                running_jobs_list = jobs.exclude(status__in=Job.STATUSES.final_statuses()).values_list(
                    "pk", flat=True
                )
                running_jobs_count = len(running_jobs_list)
                logger.info(
                    f"{running_jobs_count} out of {self.jobs.count()} jobs are still running for investigation {self.pk}"
                )
                if running_jobs_count > 0:
                    logger.info(f"Jobs {running_jobs_list} are still running for investigation {self.pk}")
                    self.status = self.STATUSES.RUNNING.value
                    self.end_time = None
                    break
            # and they are all completed
            else:
                logger.info(f"Setting investigation {self.pk} to concluded")
                self.status = self.STATUSES.CONCLUDED.value
                self.end_time = self.jobs.order_by("-finished_analysis_time").first().finished_analysis_time
        else:
            logger.info(f"Setting investigation {self.pk} to created")
            self.status = self.STATUSES.CREATED.value
            self.end_time = None
        if save:
            self.save(update_fields=["status", "end_time"])

    @classmethod
    def investigation_for_analyzable(
        cls, queryset: models.QuerySet, analyzed_object_name: str
    ) -> models.QuerySet:
        from django.db.models import Q

        jobs = Job.objects.filter(Q(finished_analysis_time__gte=now() - datetime.timedelta(days=30)))
        analyzable = Analyzable.objects.filter(name=analyzed_object_name).first()
        if not analyzable or analyzable.classification == analyzable.CLASSIFICATIONS.DOMAIN.value:
            jobs = jobs.filter(
                Q(analyzable__name=analyzed_object_name)
                | Q(analyzable__name__endswith=f".{analyzed_object_name}")
            )
        else:
            # if we have an ip, we don't need to check the subdomains
            jobs = jobs.filter(Q(analyzable__name=analyzed_object_name))
        related_job_id_list = [job_data.get_root().id for job_data in jobs]
        return queryset.filter(jobs__id__in=related_job_id_list).distinct()

    @property
    def tags(self) -> List[str]:
        return list(set(self.jobs.values_list("tags__label", flat=True)))

    @property
    def tlp(self) -> TLP:
        return (
            max(TLP[tlp_string] for tlp_string in self.jobs.values_list("tlp", flat=True))
            if self.jobs.exists()
            else TLP.CLEAR.value
        )

    @property
    def total_jobs(self) -> int:
        return sum(job.get_descendant_count() for job in self.jobs.all()) + self.jobs.count()
