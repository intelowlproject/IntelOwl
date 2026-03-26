# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm = PythonModule.objects.filter(
        module="dehashed.DehashedSearch",
        base_path="api_app.analyzers_manager.observable_analyzers",
    ).first()
    if pm:
        pm.analyzerconfigs.all().delete()
        pm.delete()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("analyzers_manager", "0186_add_update_schedule_stratosphere_firehol"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
