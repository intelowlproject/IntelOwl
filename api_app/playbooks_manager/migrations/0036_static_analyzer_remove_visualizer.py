# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.db import migrations


def migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    visualizer_config = apps.get_model("visualizers_manager", "VisualizerConfig")
    vc = visualizer_config.objects.filter(name="Yara").first()
    if vc:
        pc = playbook_config.objects.filter(name="Sample_Static_Analysis").first()
        if pc:
            vc.playbooks.remove(pc.id)
        vc.full_clean()
        vc.save()


def reverse_migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    visualizer_config = apps.get_model("visualizers_manager", "VisualizerConfig")
    vc = visualizer_config.objects.filter(name="Yara").first()
    if vc:
        pc = playbook_config.objects.filter(name="Sample_Static_Analysis").first()
        if pc:
            vc.playbooks.add(pc.id)
        vc.full_clean()
        vc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0035_playbook_config_takedown_request"),
        ("visualizers_manager", "0037_4_change_primary_key"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
