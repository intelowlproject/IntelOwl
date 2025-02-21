from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    pm = PythonModule.objects.get(
        module="firehol_iplist.FireHol_IPList",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    Parameter.objects.get(name="list_names", python_module=pm).delete()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0071_delete_last_elastic_report"),
        (
            "analyzers_manager",
            "0152_torexitaddress_trancorecord_fireholrecord_and_more",
        ),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
