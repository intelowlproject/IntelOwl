# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    for config in AnalyzerConfig.objects.filter(python_module="otx.OTX", type="file"):
        config.params = {
            "verbose": {"default": False, "type": "bool", "description": ""},
            "sections": {
                "default": ["general"],
                "type": "list",
                "description": "Sections to download. Options: [general, reputation, geo, malware, url_list, "
                "passive_dns, analysis",
            },
            "full_analysis": {
                "default": False,
                "type": "bool",
                "description": "download all the available sections for the observable type",
            },
            "timeout": {
                "default": 30,
                "type": "int",
                "description": "Timeout of the request",
            },
        }
        config.full_clean()
        config.save()


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    for config in AnalyzerConfig.objects.filter(python_module="otx.OTX", type="file"):
        config.params = {
            "verbose": {"default": False, "type": "bool", "description": ""},
        }
        config.full_clean()
        config.save()


class Migration(migrations.Migration):
    dependencies = [
        (
            "analyzers_manager",
            "0021_alter_analyzerconfig_not_supported_filetypes_and_more",
        ),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
