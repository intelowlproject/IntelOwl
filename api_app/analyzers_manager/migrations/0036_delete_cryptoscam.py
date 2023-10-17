# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.get(name="CryptoScamDB_CheckAPI").delete()

    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = PlaybookConfig.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc.analyzers.remove(*["CryptoScamDB_CheckAPI"])
    pc.full_clean()
    pc.save()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0035_analyzer_config"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
