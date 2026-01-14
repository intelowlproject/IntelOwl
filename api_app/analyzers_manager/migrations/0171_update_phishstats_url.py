from django.db import migrations


def migrate(apps, schema_editor):
    """
    Migration to document the PhishStats API URL update.
    The URL has been updated from https://phishstats.info:2096/api
    to https://api.phishstats.info/api/phishing in the PhishStats analyzer class.
    This is a code-level change and doesn't require database updates.
    """
    pass


def reverse_migrate(apps, schema_editor):
    """
    Reverse migration for PhishStats URL update.
    """
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0170_update_yaraify_archive"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
