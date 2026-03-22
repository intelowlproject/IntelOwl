# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.filter(name="TalosReputation").delete()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0175_analyzer_config_cleanbrowsing_malicious_detector"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
