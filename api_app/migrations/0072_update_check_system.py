from django.db import migrations, models
import django.utils.timezone
import json


def create_weekly_update_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=7,
        period=IntervalSchedule.DAYS,
    )

    PeriodicTask.objects.update_or_create(
        name="Weekly IntelOwl Update Check",
        defaults={
            "interval": schedule,
            "task": "api_app.tasks.intelowl_weekly_update_check",
            "kwargs": json.dumps({}),
        },
    )


def remove_weekly_update_task(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTask.objects.filter(name="Weekly IntelOwl Update Check").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("api_app", "0071_delete_last_elastic_report"),
        ("django_celery_beat", "0018_improve_crontab_helptext"),
    ]

    operations = [
        migrations.CreateModel(
            name="UpdateCheckStatus",
            fields=[
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
                    models.DateTimeField(default=django.utils.timezone.now),
                ),
                (
                    "updated_at",
                    models.DateTimeField(auto_now=True),
                ),
            ],
            options={
                "verbose_name": "Update check status",
            },
        ),
        migrations.RunPython(create_weekly_update_task, remove_weekly_update_task),
    ]
