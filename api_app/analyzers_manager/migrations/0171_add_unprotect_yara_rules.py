from django.db import migrations

def add_unprotect_yara_rules(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    try:
        # Get the Python module for YARA
        yara_module = PythonModule.objects.get(
            module="yara_scan.YaraScan",
            base_path="api_app.analyzers_manager.file_analyzers",
        )
    except PythonModule.DoesNotExist:
        print("PythonModule for YARA not found. Skipping migration.")
        return

    # Get the "repositories" parameter for this module
    try:
        param = yara_module.parameters.get(name="repositories")
    except Exception:
        print("Parameter 'repositories' not found. Skipping migration.")
        return

    # Update PluginConfig values
    for pc in PluginConfig.objects.filter(parameter=param):
        if "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip" not in pc.value:
            pc.value.append("https://yaraify.abuse.ch/yarahub/yaraify-rules.zip")
        if "https://yaraify-api.abuse.ch/download/yaraify-rules.zip" in pc.value:
            pc.value.remove("https://yaraify-api.abuse.ch/download/yaraify-rules.zip")
        pc.save()

    print("Added Unprotect.it YARA rules successfully.")


def remove_unprotect_yara_rules(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    try:
        yara_module = PythonModule.objects.get(
            module="yara_scan.YaraScan",
            base_path="api_app.analyzers_manager.file_analyzers",
        )
    except PythonModule.DoesNotExist:
        return

    try:
        param = yara_module.parameters.get(name="repositories")
    except Exception:
        return

    for pc in PluginConfig.objects.filter(parameter=param):
        if "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip" in pc.value:
            pc.value.remove("https://yaraify.abuse.ch/yarahub/yaraify-rules.zip")
        if "https://yaraify-api.abuse.ch/download/yaraify-rules.zip" not in pc.value:
            pc.value.append("https://yaraify-api.abuse.ch/download/yaraify-rules.zip")
        pc.save()
    


class Migration(migrations.Migration):

    dependencies = [
        ("analyzers_manager", "0170_update_yaraify_archive"),
    ]

    operations = [
        migrations.RunPython(add_unprotect_yara_rules, remove_unprotect_yara_rules),
    ]
