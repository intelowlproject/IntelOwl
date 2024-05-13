from django.db import migrations


def migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    analyzer_config = apps.get_model("analyzers_manager", "AnalyzerConfig")
    pc = playbook_config.objects.filter(name="Popular_URL_Reputation_Services").first()
    if pc:
        ac = analyzer_config.objects.filter(name="Tranco").first()
        if ac:
            pc.analyzers.add(ac)
        pc.full_clean()
        pc.save()


def reverse_migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    analyzer_config = apps.get_model("analyzers_manager", "AnalyzerConfig")
    pc = playbook_config.objects.filter(name="Popular_URL_Reputation_Services").first()
    if pc:
        ac = analyzer_config.objects.filter(name="Tranco").first()
        if ac:
            pc.analyzers.remove(ac)
        pc.full_clean()
        pc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0039_alter_playbookconfig_scan_check_time_and_more"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
