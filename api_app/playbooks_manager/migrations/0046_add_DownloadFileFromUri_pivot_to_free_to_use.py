# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.db import migrations


def migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    PivotConfig = apps.get_model("pivots_manager", "PivotConfig")
    pc1 = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc1.pivots.add(PivotConfig.objects.get(name="DownloadFileFromUri").id)
    pc1.full_clean()
    pc1.save()


def reverse_migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    PivotConfig = apps.get_model("pivots_manager", "PivotConfig")
    pc1 = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")
    pc1.pivots.remove(PivotConfig.objects.get(name="DownloadFileFromUri").id)
    pc1.full_clean()
    pc1.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0045_playbook_config_download_file"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
