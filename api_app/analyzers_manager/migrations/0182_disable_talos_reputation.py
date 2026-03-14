from django.db import migrations


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.filter(name="TalosReputation").update(disabled=True)


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.filter(name="TalosReputation").update(disabled=False)


class Migration(migrations.Migration):

    dependencies = [
        ("analyzers_manager", "0181_misp_published_default_none"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
