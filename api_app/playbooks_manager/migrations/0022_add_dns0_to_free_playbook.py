# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc.analyzers.add(*["DNS0_names", "DNS0_rrsets_name"])
    pc.full_clean()
    pc.save()


def reverse_migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc.analyzers.remove(*["DNS0_names", "DNS0_rrsets_name"])
    pc.full_clean()
    pc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0021_alter_playbookconfig_name_and_more"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
