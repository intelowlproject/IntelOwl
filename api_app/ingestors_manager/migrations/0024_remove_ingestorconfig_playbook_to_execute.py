# Generated by Django 4.2.11 on 2024-07-09 08:22

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        (
            "ingestors_manager",
            "0023_remove_ingestorconfig_playbook_to_execute_and_more",
        ),
    ]

    operations = [
        migrations.RemoveField(
            model_name="ingestorconfig",
            name="playbook_to_execute",
        ),
    ]