from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    pm = PythonModule.objects.get(
        module="cape_sandbox.CAPEsandbox",
        base_path="api_app.analyzers_manager.file_analyzers",
    )
    ac = AnalyzerConfig.objects.filter(python_module=pm)
    p, _ = Parameter.objects.get_or_create(
        name="requests_timeout",
        type="int",
        description="Python requests HTTP GET/POST timeout",
        is_secret=False,
        required=False,
        python_module=pm,
    )
    for real_ac in ac:
        PluginConfig.objects.get_or_create(
            owner=None,
            value=10,
            parameter=p,
            for_organization=False,
            analyzer_config=real_ac,
        )
    pm.save()


def reverse_migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    pm = PythonModule.objects.get(
        module="cape_sandbox.CAPEsandbox",
        base_path="api_app.analyzers_manager.file_analyzers",
    )
    ac = AnalyzerConfig.objects.filter(name="CapeSandbox", python_module=pm)
    p = Parameter.objects.get(python_module=pm, name="requests_timeout")
    for real_ac in ac:
        pc = PluginConfig.objects.get(parameter=p, analyzer_config=real_ac)
        pc.delete()
        real_ac.save()

    p.delete()


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0045_yaraify_fix"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
