from django.db import migrations


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PythonModule = apps.get_model("api_app", "PythonModule")

    # observables
    observable_analyzers = [
        "urlhaus.URLHaus",
        "yaraify.YARAify",
        "feodo_tracker.Feodo_Tracker",
        "threatfox.ThreatFox",
        "mb_get.MB_GET",
        "mb_google.MB_GOOGLE",
    ]
    for observable_analyzer in observable_analyzers:
        module = PythonModule.objects.get(
            module=observable_analyzer,
            base_path="api_app.analyzers_manager.observable_analyzers",
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

    # files
    yaraify_scan_module = PythonModule.objects.get(
        module="yaraify_file_scan.YARAifyFileScan",
        base_path="api_app.analyzers_manager.file_analyzers",
    )
    Parameter.objects.filter(
        name="service_api_key",
        type="str",
        is_secret=True,
        python_module=yaraify_scan_module,
    ).update(
        description="Mandatory API key to connect to abuse.ch services.",
        required=True,
    )


def reverse_migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PythonModule = apps.get_model("api_app", "PythonModule")

    # observables
    observable_analyzers = [
        "urlhaus.URLHaus",
        "yaraify.YARAify",
        "feodo_tracker.Feodo_Tracker",
        "threatfox.ThreatFox",
        "mb_get.MB_GET",
        "mb_google.MB_GOOGLE",
    ]
    for observable_analyzer in observable_analyzers:
        module = PythonModule.objects.get(
            module=observable_analyzer,
            base_path="api_app.analyzers_manager.observable_analyzers",
        )
        Parameter.objects.filter(
            name="service_api_key",
            type="str",
            is_secret=True,
            python_module=module,
        ).update(
            description="Optional API key to connect to abuse.ch services.",
            required=False,
        )

    # files
    yaraify_scan_module = PythonModule.objects.get(
        module="yaraify_file_scan.YARAifyFileScan",
        base_path="api_app.analyzers_manager.file_analyzers",
    )
    Parameter.objects.filter(
        name="service_api_key",
        type="str",
        is_secret=True,
        python_module=yaraify_scan_module,
    ).update(
        description="Optional API key to connect to abuse.ch services.",
        required=False,
    )


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("api_app", "0071_delete_last_elastic_report"),
        (
            "analyzers_manager",
            "0155_analyzer_config_debloat",
        ),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
