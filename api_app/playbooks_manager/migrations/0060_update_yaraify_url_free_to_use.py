# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.db import migrations


def migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")

    # Update the YARAify URL to the new yarahub endpoint
    repositories = (
        pc.runtime_configuration.get("analyzers", {})
        .get("Yara", {})
        .get("repositories", [])
    )

    old_url = "https://yaraify-api.abuse.ch/download/yaraify-rules.zip"
    new_url = "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip"

    if old_url in repositories:
        index = repositories.index(old_url)
        repositories[index] = new_url

    pc.full_clean()
    pc.save()


def reverse_migrate(apps, schema_editor):
    playbook_config = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = playbook_config.objects.get(name="FREE_TO_USE_ANALYZERS")

    # Revert to the old YARAify URL
    repositories = (
        pc.runtime_configuration.get("analyzers", {})
        .get("Yara", {})
        .get("repositories", [])
    )

    old_url = "https://yaraify-api.abuse.ch/download/yaraify-rules.zip"
    new_url = "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip"

    if new_url in repositories:
        index = repositories.index(new_url)
        repositories[index] = old_url

    pc.full_clean()
    pc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0059_add_ipquery_analyzer_free_to_use"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
