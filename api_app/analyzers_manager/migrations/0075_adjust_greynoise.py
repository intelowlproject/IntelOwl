from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")

    pm = PythonModule.objects.get(
        module="greynoiseintel.GreyNoiseAnalyzer",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    param = pm.parameters.get(name="api_key_name")
    param.required = False
    param.values.filter(owner=None, for_organization=False).delete()
    param.save()


def reverse_migrate(apps, schema_editor):
    ...


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("analyzers_manager", "0074_adjust_maximum_tlp"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
