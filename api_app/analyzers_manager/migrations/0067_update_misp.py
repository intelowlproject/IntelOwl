from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    pm = PythonModule.objects.get(
        module="misp.MISP", base_path="api_app.analyzers_manager.observable_analyzers"
    )

    p1 = Parameter(
        name="timeout",
        type="int",
        description="set timeout for misp instance",
        is_secret=False,
        required=True,
        python_module=pm,
    )
    p1.full_clean()
    p1.save()

    p2 = Parameter(
        name="published",
        type="bool",
        description="get only published events",
        is_secret=False,
        required=True,
        python_module=pm,
    )
    p2.full_clean()
    p2.save()

    p3 = Parameter(
        name="metadata",
        type="bool",
        description="have lighter queries but less data",
        is_secret=False,
        required=True,
        python_module=pm,
    )
    p3.full_clean()
    p3.save()

    for analyzer in pm.analyzerconfigs.all():
        pc1 = PluginConfig(
            value=5,
            analyzer_config=analyzer,
            for_organization=False,
            owner=None,
            parameter=p1,
        )
        pc1.full_clean()
        pc1.save()

        pc2 = PluginConfig(
            value=False,
            analyzer_config=analyzer,
            for_organization=False,
            owner=None,
            parameter=p2,
        )
        pc2.full_clean()
        pc2.save()

        pc3 = PluginConfig(
            value=False,
            analyzer_config=analyzer,
            for_organization=False,
            owner=None,
            parameter=p3,
        )
        pc3.full_clean()
        pc3.save()


def reverse_migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    pm = PythonModule.objects.get(
        module="misp.MISP", base_path="api_app.analyzers_manager.observable_analyzers"
    )
    parameters_to_remove = Parameter.objects.filter(
        python_module=pm, name__in=["timeout", "published", "metadata"]
    )

    PluginConfig.objects.filter(
        parameter__python_module=pm, parameter__in=parameters_to_remove
    ).delete()

    parameters_to_remove.delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0061_job_depth_analysis"),
        ("analyzers_manager", "0066_analyzer_config_phoneinfoga"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
