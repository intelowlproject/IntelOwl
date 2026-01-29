from django.db import migrations


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    PythonModule = apps.get_model("api_app", "PythonModule")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    try:
        pm = PythonModule.objects.get(
            module="phishstats.PhishStats",
            base_path="api_app.analyzers_manager.observable_analyzers",
        )
    except PythonModule.DoesNotExist:
        return

    # Create the parameter
    param, created = Parameter.objects.get_or_create(
        name="url",
        python_module=pm,
        defaults={
            "type": "str",
            "description": "PhishStats API base URL",
            "is_secret": False,
            "required": False,
        },
    )

    # For each existing Phishstats analyzer config, create a PluginConfig value
    # if it doesn't exist already
    for config in AnalyzerConfig.objects.filter(python_module=pm):
        PluginConfig.objects.get_or_create(
            analyzer_config=config,
            parameter=param,
            defaults={
                "value": "https://api.phishstats.info/api",
            },
        )


def reverse_migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PythonModule = apps.get_model("api_app", "PythonModule")

    try:
        pm = PythonModule.objects.get(
            module="phishstats.PhishStats",
            base_path="api_app.analyzers_manager.observable_analyzers",
        )
        Parameter.objects.filter(python_module=pm, name="url").delete()
    except PythonModule.DoesNotExist:
        pass


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("analyzers_manager", "0170_update_yaraify_archive"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
