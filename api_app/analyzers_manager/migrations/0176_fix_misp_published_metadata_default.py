from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    pm = PythonModule.objects.get(
        module="misp.MISP", base_path="api_app.analyzers_manager.observable_analyzers"
    )

    for param_name in ["published", "metadata"]:
        param = Parameter.objects.get(python_module=pm, name=param_name)
        # change default from False to None so that
        # "if self.published is not None" works correctly
        PluginConfig.objects.filter(
            parameter=param,
            value=False,
            owner=None,
            for_organization=False,
        ).update(value=None)


def reverse_migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    pm = PythonModule.objects.get(
        module="misp.MISP", base_path="api_app.analyzers_manager.observable_analyzers"
    )

    for param_name in ["published", "metadata"]:
        param = Parameter.objects.get(python_module=pm, name=param_name)
        # revert back to False
        PluginConfig.objects.filter(
            parameter=param,
            value=None,
            owner=None,
            for_organization=False,
        ).update(value=False)


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0062_singleton_and_elastic_report"),
        ("analyzers_manager", "0175_analyzer_config_cleanbrowsing_malicious_detector"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
