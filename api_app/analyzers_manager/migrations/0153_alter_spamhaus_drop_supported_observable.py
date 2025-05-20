from django.db import migrations


def migrate(apps, schema_editor):
    Model = apps.get_model("analyzers_manager", "AnalyzerConfig")
    plugin_name = "Spamhaus_DROP"
    try:
        obj = Model.objects.get(name=plugin_name)
        observable_supported = obj.observable_supported or []
        if "generic" not in observable_supported:
            observable_supported.append("generic")
            obj.observable_supported = observable_supported
            obj.full_clean()
            obj.save()
    except Model.DoesNotExist:
        pass


def reverse_migrate(apps, schema_editor):
    Model = apps.get_model("analyzers_manager", "AnalyzerConfig")
    plugin_name = "Spamhaus_DROP"
    try:
        obj = Model.objects.get(name=plugin_name)
        observable_supported = obj.observable_supported or []
        if "generic" in observable_supported:
            observable_supported.remove("generic")
            obj.observable_supported = observable_supported
            obj.full_clean()
            obj.save()
    except Model.DoesNotExist:
        pass


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("analyzers_manager", "0152_analyzer_config_mullvad_dns"),
    ]
    operations = [migrations.RunPython(migrate, reverse_migrate)]
