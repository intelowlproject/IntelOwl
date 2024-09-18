from django.db import migrations


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    plugin_name = "Droidlysis"

    try:
        plugin = AnalyzerConfig.objects.get(name=plugin_name)
        plugin.soft_time_limit = 60
        plugin.save()
    except AnalyzerConfig.DoesNotExist:
        pass


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    plugin_name = "Droidlysis"

    try:
        plugin = AnalyzerConfig.objects.get(name=plugin_name)
        plugin.soft_time_limit = 20
        plugin.save()
    except AnalyzerConfig.DoesNotExist:
        pass


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("analyzers_manager", "0121_analyzer_config_lnk_info"),
    ]
    operations = [migrations.RunPython(migrate, reverse_migrate)]
