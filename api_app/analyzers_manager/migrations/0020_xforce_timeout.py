# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    for config in AnalyzerConfig.objects.filter(python_module="xforce.XForce"):
        config.params["timeout"] = {
            "default": 5,
            "type": "int",
            "description": "Request timeout",
        }
        config.full_clean()
        config.save()


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    for config in AnalyzerConfig.objects.filter(python_module="xforce.XForce"):
        config.params = {
            "malware_only": {
                "default": False,
                "type": "bool",
                "description": "Performs lookup only against 'malware' endpoints to save some quota",
            }
        }
        config.full_clean()
        config.save()


class Migration(migrations.Migration):

    dependencies = [
        (
            "analyzers_manager",
            "0019_dnstwist_params",
        ),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
