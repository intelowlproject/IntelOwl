from django.db import migrations


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PythonModule = apps.get_model("api_app", "PythonModule")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    IngestorConfig = apps.get_model("ingestors_manager", "IngestorConfig")

    ic = IngestorConfig.objects.get(name="ThreatFox")
    pm = PythonModule.objects.get(
        module="threatfox.ThreatFox", base_path="api_app.ingestors_manager.ingestors"
    )
    if not Parameter.objects.filter(python_module=pm, name="url"):
        p = Parameter(
            name="url",
            type="str",
            description="API endpoint",
            is_secret=False,
            required=True,
            python_module=pm,
        )
        p.full_clean()
        p.save()

        pc = PluginConfig(
            value="https://threatfox-api.abuse.ch/api/v1/",
            ingestor_config=ic,
            for_organization=False,
            owner=None,
            parameter=p,
        )
        pc.full_clean()
        pc.save()


def reverse_migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PythonModule = apps.get_model("api_app", "PythonModule")

    pm = PythonModule.objects.get(
        module="threatfox.ThreatFox", base_path="api_app.ingestors_manager.ingestors"
    )
    Parameter.objects.filter(python_module=pm, name="url").delete()


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("ingestors_manager", "0019_ingestor_config_malwarebazaar"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
