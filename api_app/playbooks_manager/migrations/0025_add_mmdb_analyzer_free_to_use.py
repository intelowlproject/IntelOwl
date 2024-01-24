# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.db import migrations


def migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc.analyzers.add(*["Mmdb_server"])
    pc.full_clean()
    pc.save()


def reverse_migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc.analyzers.remove(*["Mmdb_server"])
    pc.full_clean()
    pc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0024_4_change_primary_key"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
