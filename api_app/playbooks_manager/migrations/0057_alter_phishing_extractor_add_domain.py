from django.db import migrations


def migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    config = PlaybookConfig.objects.get(name="PhishingExtractor")
    config.type = [
        "url",
        "domain",
    ]
    config.full_clean()
    config.save()


def reverse_migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    config = PlaybookConfig.objects.get(name="PhishingExtractor")
    config.type = [
        "url",
    ]
    config.full_clean()
    config.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0056_download_sample_vt"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
