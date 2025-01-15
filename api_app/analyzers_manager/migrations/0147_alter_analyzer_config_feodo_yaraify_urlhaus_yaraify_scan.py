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
        Parameter.objects.create(
            name="service_api_key",
            type="str",
            description="Optional API key to connect to abuse.ch services.",
            is_secret=True,
            required=False,
            python_module=module,
        )

    # files
    yaraify_scan_module = PythonModule.objects.get(
        module="yaraify_file_scan.YARAifyFileScan",
        base_path="api_app.analyzers_manager.file_analyzers",
    )
    Parameter.objects.create(
        name="service_api_key",
        type="str",
        description="Optional API key to connect to abuse.ch services.",
        is_secret=True,
        required=False,
        python_module=yaraify_scan_module,
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
        Parameter.objects.get(
            name="service_api_key",
            type="str",
            description="Optional API key to connect to abuse.ch services.",
            is_secret=True,
            required=False,
            python_module=module,
        ).delete()

    # files
    yaraify_scan_module = PythonModule.objects.get(
        module="yaraify_file_scan.YARAifyFileScan",
        base_path="api_app.analyzers_manager.file_analyzers",
    )
    Parameter.objects.get(
        name="service_api_key",
        type="str",
        description="Optional API key to connect to abuse.ch services.",
        is_secret=True,
        required=False,
        python_module=yaraify_scan_module,
    ).delete()


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("api_app", "0065_job_mpnodesearch"),
        (
            "analyzers_manager",
            "0146_analyzer_config_wad",
        ),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
