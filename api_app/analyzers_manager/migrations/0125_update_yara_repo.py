from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    pm = PythonModule.objects.get(
        module="yara_scan.YaraScan",
        base_path="api_app.analyzers_manager.file_analyzers",
    )
    param = pm.parameters.get(name="repositories")
    pc = PluginConfig.objects.get(parameter=param)
    pc.value.append("https://yaraify-api.abuse.ch/download/yaraify-rules.zip")
    pc.value.remove("https://yaraify-api.abuse.ch/yarahub/yaraify-rules.zip")
    pc.save()


def reverse_migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    pm = PythonModule.objects.get(
        module="yara_scan.YaraScan",
        base_path="api_app.analyzers_manager.file_analyzers",
    )
    param = pm.parameters.get(name="repositories")
    pc = PluginConfig.objects.get(parameter=param)
    pc.value.remove("https://yaraify-api.abuse.ch/download/yaraify-rules.zip")
    pc.value.append("https://yaraify-api.abuse.ch/yarahub/yaraify-rules.zip")
    pc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0124_analyzer_config_androguard"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
