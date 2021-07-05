# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from os import remove, path

from django.db import models
from django.db.models.signals import pre_delete
from django.contrib.postgres import fields as pg_fields
from django.utils import timezone
from django.dispatch import receiver


from .exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import AnalyzerReport


def file_directory_path(instance, filename):
    now = timezone.now().strftime("%Y_%m_%d_%H_%M_%S")
    return f"job_{now}_{filename}"


STATUS = [
    ("pending", "pending"),
    ("running", "running"),
    ("reported_without_fails", "reported_without_fails"),
    ("reported_with_fails", "reported_with_fails"),
    ("failed", "failed"),
    ("killed", "killed"),
]


class Tag(models.Model):
    label = models.CharField(max_length=50, blank=False, null=False, unique=True)
    color = models.CharField(max_length=7, blank=False, null=False, unique=True)

    def __str__(self):
        return f'Tag(label="{self.label}")'


class Job(models.Model):
    class Meta:
        indexes = [
            models.Index(
                fields=[
                    "md5",
                    "status",
                ]
            ),
        ]

    source = models.CharField(max_length=50, blank=False, default="none")
    is_sample = models.BooleanField(blank=False, default=False)
    md5 = models.CharField(max_length=32, blank=False)
    observable_name = models.CharField(max_length=512, blank=True)
    observable_classification = models.CharField(max_length=12, blank=True)
    file_name = models.CharField(max_length=512, blank=True)
    file_mimetype = models.CharField(max_length=80, blank=True)
    status = models.CharField(
        max_length=32, blank=False, choices=STATUS, default="pending"
    )
    analyzers_requested = pg_fields.ArrayField(
        models.CharField(max_length=128), blank=True, default=list
    )
    run_all_available_analyzers = models.BooleanField(blank=False, default=False)
    analyzers_to_execute = pg_fields.ArrayField(
        models.CharField(max_length=128), blank=True, default=list
    )
    connectors_to_execute = pg_fields.ArrayField(
        models.CharField(max_length=128), blank=True, default=list
    )
    received_request_time = models.DateTimeField(auto_now_add=True)
    finished_analysis_time = models.DateTimeField(blank=True, null=True)
    force_privacy = models.BooleanField(blank=False, default=False)
    disable_external_analyzers = models.BooleanField(blank=False, default=False)
    errors = pg_fields.ArrayField(
        models.CharField(max_length=900), blank=True, default=list, null=True
    )
    file = models.FileField(blank=True, upload_to=file_directory_path)
    tags = models.ManyToManyField(Tag, related_name="jobs", blank=True)
    runtime_configuration = models.JSONField(default=dict, null=True, blank=True)

    @classmethod
    def object_by_job_id(cls, job_id, transaction=False):
        try:
            if transaction:
                job_object = cls.objects.select_for_update().get(id=job_id)
            else:
                job_object = cls.objects.get(id=job_id)
        except cls.DoesNotExist:
            raise AnalyzerRunException(f"No Job with ID:{job_id} retrieved")

        return job_object

    def __str__(self):
        if self.is_sample:
            return f'Job("{self.file_name}")'
        return f'Job("{self.observable_name}")'

    @classmethod
    def init_report(cls, name, job_id):
        report_obj = AnalyzerReport(
            analyzer_name=name,
            job=cls.object_by_job_id(job_id),
            report={},
            errors=[],
        )
        report_obj.status = report_obj.Statuses.PENDING.name

        return report_obj


@receiver(pre_delete, sender=Job)
def delete_file(sender, instance, **kwargs):
    if instance.file:
        if path.isfile(instance.file.path):
            remove(instance.file.path)
