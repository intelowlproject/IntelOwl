from django.db import models
from django.contrib.postgres import fields as postgres_fields


class AnalyzerReport(models.Model):
    STATUS_CHOICES = (
        ("pending", "pending"),
        ("running", "running"),
        ("failed", "failed"),
        ("success", "success"),
    )

    analyzer_name = models.CharField(max_length=128, blank=False, unique=True)
    job = models.ForeignKey(
        "api_app.Job", related_name="analyzer_reports", on_delete=models.CASCADE
    )

    status = models.CharField(
        max_length=50,
        choices=STATUS_CHOICES,
        blank=False,
    )
    report = models.JSONField(default=dict, blank=False)
    errors = postgres_fields.ArrayField(
        models.CharField(max_length=512, blank=True, default=list)
    )
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()

    def __str__(self):
        return f"Analyzer({self.connector})-{self.job}"
