from django.db import migrations


def add_unprotect_url(apps, schema_editor):

    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")

    try:
        yara_module = PythonModule.objects.get(name="yara_scan")
      
        parameter = Parameter.objects.get(module=yara_module, name="repositories")
    except (PythonModule.DoesNotExist, Parameter.DoesNotExist):
        return

    unprotect_url = "https://unprotect.it/api/detection_rules/"
    plugin_configs = PluginConfig.objects.filter(parameter=parameter)

    for pc in plugin_configs:
    
        value = pc.value or []
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
