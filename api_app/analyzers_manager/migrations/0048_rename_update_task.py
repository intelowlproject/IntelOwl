# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    for task in PeriodicTask.objects.filter(name__endswith="Analyzer"):
        task.name = (
            task.name.split("Analyzer")[0] + "Update" + task.analyzer.__class__.__name__
        )
        task.save()


def reverse_migrate(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    for task in PeriodicTask.objects.filter(name__endswith="AnalyzerConfig"):
        task.name = task.name.split("Update")[0] + "Analyzer"
        task.save()


class Migration(migrations.Migration):
    dependencies = [
        (
            "analyzers_manager",
            "0047_vt_removed_force_active_scan",
        ),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
