# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    # New analyzers to add
    new_analyzers = ["DNS4EU", "DNS4EU_Malicious_Detector"]
    analyzer_objs = list(AnalyzerConfig.objects.filter(name__in=new_analyzers))

    # Playbooks to update
    playbook_names = ["FREE_TO_USE_ANALYZERS", "Dns"]

    for pb_name in playbook_names:
        pc = PlaybookConfig.objects.filter(name=pb_name).first()
        if pc:
            for analyzer in analyzer_objs:
                pc.analyzers.add(analyzer)
            pc.full_clean()
            pc.save()


def reverse_migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    new_analyzers = ["DNS4EU", "DNS4EU_Malicious_Detector"]
    analyzer_objs = list(AnalyzerConfig.objects.filter(name__in=new_analyzers))

    playbook_names = ["FREE_TO_USE_ANALYZERS", "Dns"]

    for pb_name in playbook_names:
        pc = PlaybookConfig.objects.filter(name=pb_name).first()
        if pc:
            for analyzer in analyzer_objs:
                pc.analyzers.remove(analyzer)
            pc.full_clean()
            pc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0060_update_yaraify_url_free_to_use"),
        ("analyzers_manager", "0173_replace_dns0_with_dns4eu"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
