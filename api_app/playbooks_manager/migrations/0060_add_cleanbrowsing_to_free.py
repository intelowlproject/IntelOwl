# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    # 1. Get the Free Playbook
    pc = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")

    # 2. Get your CleanBrowsing Analyzer
    # (The name "CleanBrowsing" comes from the typename class attribute in your python file)
    clean_browsing = AnalyzerConfig.objects.get(name="CleanBrowsing")

    # 3. Add it to the list
    pc.analyzers.add(clean_browsing.id)

    # 4. Save
    pc.full_clean()
    pc.save()


def reverse_migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    pc = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")
    clean_browsing = AnalyzerConfig.objects.get(name="CleanBrowsing")

    # Remove it if we roll back
    pc.analyzers.remove(clean_browsing.id)
    pc.full_clean()
    pc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0059_add_ipquery_analyzer_free_to_use"),
        ("analyzers_manager", "0171_analyzer_config_cleanbrowsing"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
