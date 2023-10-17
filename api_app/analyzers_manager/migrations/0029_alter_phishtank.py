# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations

from api_app.analyzers_manager.constants import ObservableTypes


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    for config in AnalyzerConfig.objects.filter(python_module="phishtank.Phishtank"):
        config.observable_supported = [ObservableTypes.DOMAIN, ObservableTypes.URL]
        config.full_clean()
        config.save()


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    for config in AnalyzerConfig.objects.filter(python_module="phishtank.Phishtank"):
        config.observable_supported = [ObservableTypes.URL]
        config.full_clean()
        config.save()


class Migration(migrations.Migration):
    dependencies = [
        (
            "analyzers_manager",
            "0028_alter_analyzerconfig_name",
        ),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
