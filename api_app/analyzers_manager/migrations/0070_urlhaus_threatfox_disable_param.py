from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    pm = PythonModule.objects.get(
        module="urlhaus.URLHaus",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    p = Parameter(
        name="disable",
        type="bool",
        description="Disable the analyzer at runtime",
        is_secret=False,
        required=False,
        python_module=pm,
    )
    p.full_clean()
    p.save()

    for analyzer in pm.analyzerconfigs.all():
        pc1 = PluginConfig(
            value=False,
            analyzer_config=analyzer,
            for_organization=False,
            owner=None,
            parameter=p,
        )
        pc1.full_clean()
        pc1.save()

    pm = PythonModule.objects.get(
        module="threatfox.ThreatFox",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    p = Parameter(
        name="disable",
        type="bool",
        description="Disable the analyzer at runtime",
        is_secret=False,
        required=False,
        python_module=pm,
    )
    p.full_clean()
    p.save()

    for analyzer in pm.analyzerconfigs.all():
        pc1 = PluginConfig(
            value=False,
            analyzer_config=analyzer,
            for_organization=False,
            owner=None,
            parameter=p,
        )
        pc1.full_clean()
        pc1.save()


def reverse_migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")

    pm = PythonModule.objects.get(
        module="urlhaus.URLHaus",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    Parameter.objects.get(name="disable", python_module=pm).delete()

    pm = PythonModule.objects.get(
        module="threatfox.ThreatFox",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    Parameter.objects.get(name="disable", python_module=pm).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0061_job_depth_analysis"),
        ("analyzers_manager", "0069_analyzer_config_bgp_ranking"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
