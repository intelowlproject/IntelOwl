# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    # Update UrlScan_Submit_Result to support both url and domain
    urlscan = AnalyzerConfig.objects.get(name="UrlScan_Submit_Result")
    urlscan.observable_supported = ["url", "domain"]
    urlscan.full_clean()
    urlscan.save()


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    # Revert UrlScan_Submit_Result to only support url
    urlscan = AnalyzerConfig.objects.get(name="UrlScan_Submit_Result")
    urlscan.observable_supported = ["url"]
    urlscan.full_clean()
    urlscan.save()


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0002_0146_analyzer_config_zoomeye"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
