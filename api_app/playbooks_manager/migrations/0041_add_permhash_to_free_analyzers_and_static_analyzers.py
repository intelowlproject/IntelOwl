# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.db import migrations


def migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    pc1 = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc1.analyzers.add(AnalyzerConfig.objects.get(name="Permhash").id)
    pc1.full_clean()
    pc1.save()
    pc2 = playbook_config.objects.get(name="Sample_Static_Analysis")
    pc2.analyzers.add(AnalyzerConfig.objects.get(name="Permhash").id)
    pc2.full_clean()
    pc2.save()


def reverse_migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    pc1 = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc1.analyzers.remove(AnalyzerConfig.objects.get(name="Permhash").id)
    pc1.full_clean()
    pc1.save()
    pc2 = playbook_config.objects.get(name="Sample_Static_Analysis")
    pc2.analyzers.remove(AnalyzerConfig.objects.get(name="Permhash").id)
    pc2.full_clean()
    pc2.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0040_alter_domain_reputation_playbook"),
        ("analyzers_manager", "0085_analyzer_config_permhash"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
