from django.db import migrations


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PythonModule = apps.get_model("api_app", "PythonModule")

    ingestors = [
        "malware_bazaar.MalwareBazaar",
        "threatfox.ThreatFox",
    ]
    for ingestor in ingestors:
        module = PythonModule.objects.get(
            module=ingestor,
            base_path="api_app.ingestors_manager.ingestors",
        )
        Parameter.objects.filter(
            name="service_api_key",
            type="str",
            is_secret=True,
            python_module=module,
        ).update(
            description="Mandatory API key to connect to abuse.ch services.",
            required=True,
        )


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("api_app", "0071_delete_last_elastic_report"),
        ("ingestors_manager", "0029_ingestor_config_malshare"),
    ]

    operations = [migrations.RunPython(migrate, migrations.RunPython.noop)]
