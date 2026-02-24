from django.db import migrations


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm = PythonModule.objects.get(
        module="phishing.phishing_extractor.PhishingExtractor",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    param = Parameter.objects.create(
        name="phishing_engine",
        type="str",
        description=(
            "Browser engine used for phishing analysis. "
            'Accepted values: "selenium" (default, Selenium-Wire) '
            'or "playwright" (Playwright). Both produce the same '
            "output schema."
        ),
        is_secret=False,
        required=False,
        python_module=pm,
    )
    for config in pm.analyzerconfigs.all():
        PluginConfig.objects.create(
            parameter=param,
            analyzer_config=config,
            value="selenium",
            owner=None,
            for_organization=False,
        )


def reverse_migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm = PythonModule.objects.get(
        module="phishing.phishing_extractor.PhishingExtractor",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    Parameter.objects.filter(
        name="phishing_engine",
        python_module=pm,
    ).delete()


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("analyzers_manager", "0177_update_urlscan_observable_supported"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
