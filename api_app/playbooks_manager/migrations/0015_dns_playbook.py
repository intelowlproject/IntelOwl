# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = PlaybookConfig.objects.create(
        type=["domain"],
        name="Dns",
        description="Retrieve information from DNS about the domain",
    )
    pc.analyzers.set(
        [
            "Classic_DNS",
            "CloudFlare_DNS",
            "DNS0_EU",
            "Google_DNS",
            "Quad9_DNS",
            "CloudFlare_Malicious_Detector",
            "DNS0_EU_Malicious_Detector",
            "Quad9_Malicious_Detector",
        ]
    )
    pc.full_clean()


def reverse_migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    PlaybookConfig.objects.get(name="Dns").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0014_remove_old_playbook"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
