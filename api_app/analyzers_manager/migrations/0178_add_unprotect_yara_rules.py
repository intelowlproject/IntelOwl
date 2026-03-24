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
        parameter = Parameter.objects.get(
            python_module=yara_module,
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
        parameter = Parameter.objects.get(
            python_module=yara_module, name="repositories"
        )
    except (PythonModule.DoesNotExist, Parameter.DoesNotExist):
        return
    unprotect_url = "https://unprotect.it/api/detection_rules/"
    plugin_configs = PluginConfig.objects.filter(parameter=parameter)
    for pc in plugin_configs:
        existing_value = pc.value

        # If the value is a list, remove the Unprotect URL if present,
        # leaving all other repository entries untouched.
        if isinstance(existing_value, list):
            if unprotect_url in existing_value:
                value = [v for v in existing_value if v != unprotect_url]
                pc.value = value
                pc.save(update_fields=["value"])

        # If the value is a string and exactly matches the Unprotect URL,
        # clear it. Do not modify other string values.
        elif isinstance(existing_value, str):
            if existing_value == unprotect_url:
                pc.value = ""
                pc.save(update_fields=["value"])

class Migration(migrations.Migration):

    dependencies = [
        ("analyzers_manager", "0177_update_urlscan_observable_supported"),
    ]
    operations = [
        migrations.RunPython(add_unprotect_url, remove_unprotect_url),
    ]
