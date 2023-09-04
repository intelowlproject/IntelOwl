# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = PlaybookConfig.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc.analyzers.add(*["Quad9_DNS", "DNS0_EU", "CloudFlare_DNS"])
    pc.full_clean()
    pc.save()


def reverse_migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = PlaybookConfig.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc.analyzers.remove(*["Quad9_DNS", "DNS0_EU", "CloudFlare_DNS"])
    pc.full_clean()
    pc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0007_fix_static_analysis"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
