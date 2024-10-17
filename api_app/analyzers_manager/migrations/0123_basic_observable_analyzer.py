from django.db import migrations


def migrate_python_module_pivot(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm, _ = PythonModule.objects.update_or_create(
        module="basic_observable_analyzer.BasicObservableAnalyzer",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    Parameter = apps.get_model("api_app", "Parameter")
    Parameter.objects.get_or_create(
        name="url",
        type="str",
        python_module=pm,
        is_secret=False,
        required=True,
        defaults={
            "description": "URL of the instance you want to connect to",
        },
    )
    Parameter.objects.get_or_create(
        name="api_key_name",
        type="str",
        python_module=pm,
        is_secret=True,
        required=False,
        defaults={
            "description": "API key required for authentication",
        },
    )
    Parameter.objects.get_or_create(
        name="headers",
        type="dict",
        python_module=pm,
        is_secret=False,
        required=False,
        defaults={
            "description": "Headers used for the request",
        },
    )
    Parameter.objects.get_or_create(
        name="http_method",
        type="str",
        python_module=pm,
        is_secret=False,
        required=True,
        defaults={
            "description": "HTTP method used for the request",
        },
    )
    Parameter.objects.get_or_create(
        name="params",
        type="dict",
        python_module=pm,
        is_secret=False,
        required=False,
        defaults={
            "description": "Params used for the query string or request payload",
        },
    )
    Parameter.objects.get_or_create(
        name="certificate",
        type="str",
        python_module=pm,
        is_secret=True,
        required=False,
        defaults={
            "description": "Instance SSL certificate (multiline string).",
        },
    )


def reverse_migrate_module_pivot(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    PythonModule.objects.get(
        module="basic_observable_analyzer.BasicObservableAnalyzer",
        base_path="api_app.analyzers_manager.observable_analyzers",
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0122_alter_soft_time_limit"),
    ]
    operations = [
        migrations.RunPython(migrate_python_module_pivot, reverse_migrate_module_pivot)
    ]
