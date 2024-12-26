# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.db import migrations


def migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    pc = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc.analyzers.add(AnalyzerConfig.objects.get(name="UltraDNS_DNS").id)
    pc.full_clean()
    pc.save()


def reverse_migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    pc = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc.analyzers.remove(AnalyzerConfig.objects.get(name="UltraDNS_DNS").id)
    pc.full_clean()
    pc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0056_download_sample_vt"),
        ("analyzers_manager", "0144_analyzer_config_ultradns_dns"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
