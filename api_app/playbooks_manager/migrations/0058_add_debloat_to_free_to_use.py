from django.db import migrations


def add_debloat_to_free_to_use(apps, schema_editor):
    # Get the PlaybookConfig and AnalyzerConfig models from the migration context.
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    # Retrieve the playbook for free-to-use analyzers.
    playbook = PlaybookConfig.objects.get(name="FREE_TO_USE_ANALYZERS")

    # Retrieve the Debloat analyzer configuration. It should have been created earlier.
    try:
        debloat_config = AnalyzerConfig.objects.get(name="debloat")
    except AnalyzerConfig.DoesNotExist:
        # If the Debloat analyzer configuration does not exist, we skip adding it.
        debloat_config = None

    if debloat_config:
        # Use .add() method on the ManyRelatedManager to add the debloat analyzer.
        playbook.analyzers.add(debloat_config)
    playbook.full_clean()
    playbook.save()


def reverse_migration(apps, schema_editor):
    # Get the models from the migration context.
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    playbook = PlaybookConfig.objects.get(name="FREE_TO_USE_ANALYZERS")
    try:
        debloat_config = AnalyzerConfig.objects.get(name="debloat")
    except AnalyzerConfig.DoesNotExist:
        debloat_config = None

    if debloat_config:
        # Remove the debloat analyzer using the .remove() method.
        playbook.analyzers.remove(debloat_config)
    playbook.full_clean()
    playbook.save()


class Migration(migrations.Migration):

    # Adjust the dependency to one that does not create a circular dependency.
    dependencies = [
        ("playbooks_manager", "0057_alter_phishing_extractor_add_domain"),
    ]

    operations = [
        migrations.RunPython(add_debloat_to_free_to_use, reverse_migration),
    ]
