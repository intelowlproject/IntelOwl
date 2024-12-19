from django.db import migrations


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    plugin_name = "Validin"
    correct_description = "[Validin's](https://app.validin.com) API for threat researchers, teams, and companies to investigate historic and current data describing the structure and composition of the internet."

    try:
        plugin = AnalyzerConfig.objects.get(name=plugin_name)
        plugin.description = correct_description
        plugin.save()
    except AnalyzerConfig.DoesNotExist:
        pass


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    plugin_name = "Validin"
    original_description = "(Validin's)[https://app.validin.com/docs] API for threat researchers, teams, and companies to investigate historic and current data describing the structure and composition of the internet."

    try:
        plugin = AnalyzerConfig.objects.get(name=plugin_name)
        plugin.description = original_description
        plugin.save()
    except AnalyzerConfig.DoesNotExist:
        pass


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("analyzers_manager", "0091_analyzer_config_vulners"),
    ]
    operations = [migrations.RunPython(migrate, reverse_migrate)]
