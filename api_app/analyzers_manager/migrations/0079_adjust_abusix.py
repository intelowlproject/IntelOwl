from django.db import migrations


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    AnalyzerConfig.objects.filter(
        name="Abusix",
    ).update(health_check_status=True)


def reverse_migrate(apps, schema_editor):
    ...


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("analyzers_manager", "0078_analyzer_config_hfinger"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
