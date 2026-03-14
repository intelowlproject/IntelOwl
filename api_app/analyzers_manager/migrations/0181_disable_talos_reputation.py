from django.db import migrations


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.filter(name="TalosReputation").update(disabled=True)


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.filter(name="TalosReputation").update(disabled=False)


class Migration(migrations.Migration):

    dependencies = [
        ("analyzers_manager", "0180_add_local_db_models_phishing_army"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
