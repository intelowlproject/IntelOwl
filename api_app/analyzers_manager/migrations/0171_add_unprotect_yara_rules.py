# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.db import migrations

def add_unprotect_url(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    try:
        yara_module = PythonModule.objects.get(
            module="yara_scan.YaraScan",
            base_path="api_app.analyzers_manager.file_analyzers",
            )
        parameter = Parameter.objects.get(python_module=yara_module,
            name="repositories",
         )
    except (PythonModule.DoesNotExist, Parameter.DoesNotExist):
        return

    unprotect_url = "https://unprotect.it/api/detection_rules/"
    plugin_configs = PluginConfig.objects.filter(parameter=parameter)

    for pc in plugin_configs:
        value = pc.value if isinstance(pc.value, list) else []
        if unprotect_url not in value:
            value.append(unprotect_url)
            pc.value = value
            pc.save(update_fields=["value"])


def remove_unprotect_url(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    try:
        yara_module = PythonModule.objects.get(
            module="yara_scan.YaraScan",
            base_path="api_app.analyzers_manager.file_analyzers",
        )
        parameter = Parameter.objects.get(python_module=yara_module, name="repositories")
    except (PythonModule.DoesNotExist, Parameter.DoesNotExist):
        return
    unprotect_url = "https://unprotect.it/api/detection_rules/"
    plugin_configs = PluginConfig.objects.filter(parameter=parameter)
    for pc in plugin_configs:
        if isinstance(pc.value, list) and unprotect_url in pc.value:
            value = list(pc.value)
            value.remove(unprotect_url)
            pc.value = value
            pc.save(update_fields=["value"])

class Migration(migrations.Migration):

    dependencies = [
        ('analyzers_manager', '0171_analyzer_config_hibpbreaches'),
    ]
    operations = [
        migrations.RunPython(add_unprotect_url, remove_unprotect_url),
    ]