# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    pm = PythonModule.objects.filter(
        module="feodo_tracker.Feodo_Tracker",
        base_path="api_app.analyzers_manager.observable_analyzers",
    ).first()
    if pm:
        task_ids = [getattr(pm, "update_task_id", None)]
        task_ids.extend(getattr(c, "health_check_task_id", None) for c in pm.analyzerconfigs.all())
        PeriodicTask.objects.filter(id__in=[t for t in task_ids if t]).delete()

        pm.analyzerconfigs.all().delete()
        pm.delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("analyzers_manager", "0197_update_opencti_description"),
        ("django_celery_beat", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(migrate, migrations.RunPython.noop),
    ]
