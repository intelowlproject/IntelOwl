import json

import django.utils.timezone
from django.db import migrations, models


def create_weekly_update_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=7,
        period="days",
    )

    PeriodicTask.objects.update_or_create(
        name="Weekly IntelOwl Update Check",
        defaults={
            "interval": schedule,
            "task": "api_app.core.tasks.scheduled_update_check",
            "kwargs": json.dumps({}),
            "enabled": True,
        },
    )


def remove_weekly_update_task(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTask.objects.filter(name="Weekly IntelOwl Update Check").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0071_delete_last_elastic_report"),
        ("django_celery_beat", "__latest__"),
    ]

    operations = [
        migrations.CreateModel(
            name="UpdateCheckStatus",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "latest_version",
                    models.CharField(
                        max_length=20,
                        null=True,
                        blank=True,
                        help_text="Latest version detected during update check",
                    ),
                ),
                (
                    "notified",
                    models.BooleanField(
                        default=False,
                        help_text="Whether notification has already been sent",
                    ),
                ),
                (
                    "last_checked_at",
                    models.DateTimeField(
                        null=True,
                        blank=True,
                        help_text="Last time update check ran",
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(
                        default=django.utils.timezone.now,
                        editable=False,
                    ),
                ),
                (
                    "updated_at",
                    models.DateTimeField(auto_now=True),
                ),
            ],
            options={
                "verbose_name": "Update check info",
            },
        ),
        migrations.RunPython(
            create_weekly_update_task,
            remove_weekly_update_task,
        ),
    ]
