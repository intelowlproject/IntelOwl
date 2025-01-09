# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.db import migrations


def migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    pc = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc2 = playbook_config.objects.get(name="Dns")
    pc.analyzers.add(
        AnalyzerConfig.objects.get(name="UltraDNS_DNS").id,
        AnalyzerConfig.objects.get(name="UltraDNS_Malicious_Detector").id,
    )
    pc2.analyzers.add(
        AnalyzerConfig.objects.get(name="UltraDNS_DNS").id,
        AnalyzerConfig.objects.get(name="UltraDNS_Malicious_Detector").id,
    )
    pc.full_clean()
    pc.save()
    pc2.full_clean()
    pc2.save()


def reverse_migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    pc = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc2 = playbook_config.objects.get(name="Dns")

    pc.analyzers.remove(
        AnalyzerConfig.objects.get(name="UltraDNS_DNS").id,
        AnalyzerConfig.objects.get(name="UltraDNS_Malicious_Detector").id,
    )
    pc.full_clean()
    pc.save()
    pc2.analyzers.remove(
        AnalyzerConfig.objects.get(name="UltraDNS_DNS").id,
        AnalyzerConfig.objects.get(name="UltraDNS_Malicious_Detector").id,
    )
    pc2.full_clean()
    pc2.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0057_alter_phishing_extractor_add_domain"),
        ("analyzers_manager", "0145_analyzer_config_ultradns_malicious_detector"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
