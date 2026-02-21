from django.db import migrations

def add_unprotect_url(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    try:
        # 1. PythonModule uses 'module' to identify the class path
        yara_module = PythonModule.objects.get(module="yara_scan.YaraScan")
        
        # 2. Parameter uses 'python_module' as the foreign key (FIXED HERE)
        parameter = Parameter.objects.get(python_module=yara_module, name="repositories")
    except (PythonModule.DoesNotExist, Parameter.DoesNotExist):
        return

    unprotect_url = "https://unprotect.it/api/detection_rules/"
    plugin_configs = PluginConfig.objects.filter(parameter=parameter)

    for pc in plugin_configs:
        # Standard safety check for list types
        value = pc.value if isinstance(pc.value, list) else []
        if unprotect_url not in value:
            value.append(unprotect_url)
            pc.value = value
            pc.save(update_fields=["value"])

class Migration(migrations.Migration):
    dependencies = [
        ('analyzers_manager', '0176_analyzer_config_macho_info'),
    ]
    operations = [
        migrations.RunPython(add_unprotect_url),
    ]