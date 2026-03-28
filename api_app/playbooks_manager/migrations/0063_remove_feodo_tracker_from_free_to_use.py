# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    pc = PlaybookConfig.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc.analyzers.remove(AnalyzerConfig.objects.get(name="Feodo_Tracker").id)
    pc.full_clean()
    pc.save()


def reverse_migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    pc = PlaybookConfig.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc.analyzers.add(AnalyzerConfig.objects.get(name="Feodo_Tracker").id)
    pc.full_clean()
    pc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0062_add_cleanbrowsing_to_free_to_use"),
        ("analyzers_manager", "0176_disable_feodo_tracker"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
