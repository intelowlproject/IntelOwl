from django.db import migrations


OLD_NAME = "Dns"
NEW_NAME = "DNS"


def forwards(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")

    try:
        old = PlaybookConfig.objects.get(name=OLD_NAME)
    except PlaybookConfig.DoesNotExist:
        return

    # If the new record already exists, prefer keeping it and deleting the old one.
    if PlaybookConfig.objects.filter(name=NEW_NAME).exists():
        old.delete()
        return

    old.name = NEW_NAME
    old.save(update_fields=["name"])


def backwards(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")

    try:
        new = PlaybookConfig.objects.get(name=NEW_NAME)
    except PlaybookConfig.DoesNotExist:
        return

    if PlaybookConfig.objects.filter(name=OLD_NAME).exists():
        new.delete()
        return

    new.name = OLD_NAME
    new.save(update_fields=["name"])


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0062_add_cleanbrowsing_to_free_to_use"),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
