# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm = PythonModule.objects.filter(
        module="talos.Talos",
        base_path="api_app.analyzers_manager.observable_analyzers",
    ).first()
    if pm:
        pm.analyzerconfigs.all().delete()
        pm.delete()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0071_delete_last_elastic_report"),
        ("analyzers_manager", "0175_analyzer_config_cleanbrowsing_malicious_detector"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
