# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm = PythonModule.objects.filter(
        module="feodo_tracker.Feodo_Tracker",
        base_path="api_app.analyzers_manager.observable_analyzers",
    ).first()
    if pm:
        pm.analyzerconfigs.all().delete()
        pm.delete()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0189_update_capa_timeout"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
