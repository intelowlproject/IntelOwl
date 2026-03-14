from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    pm = PythonModule.objects.get(
        module="misp.MISP",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    param = Parameter.objects.get(python_module=pm, name="published")
    param.required = False
    param.full_clean()
    param.save()

    PluginConfig.objects.filter(
        parameter=param,
        for_organization=False,
        owner=None,
    ).update(value=None)


def reverse_migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    pm = PythonModule.objects.get(
        module="misp.MISP",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    param = Parameter.objects.get(python_module=pm, name="published")
    param.required = True
    param.full_clean()
    param.save()

    PluginConfig.objects.filter(
        parameter=param,
        for_organization=False,
        owner=None,
    ).update(value=False)


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0061_job_depth_analysis"),
        ("analyzers_manager", "0180_add_local_db_models_phishing_army"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
