# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


# Logic to apply
def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PythonModule = apps.get_model("api_app", "PythonModule")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    try:
        pm = PythonModule.objects.get(module="PhishStats")
    except PythonModule.DoesNotExist:
        return

    # Create the parameter
    param, _ = Parameter.objects.get_or_create(
        name="url",
        python_module=pm,
        defaults={
            "type": "str",
            "description": "PhishStats API base URL",
            "is_secret": False,
            "required": False,
            "default_value": "https://api.phishstats.info/api/phishing",
        },
    )

    if not AnalyzerConfig.objects.filter(python_module=pm).exists():
        return

    # Add parameter to the Analyzer Configuration
    for config in AnalyzerConfig.objects.filter(python_module=pm):
        config.parameters.add(param)
        config.save()


# Logic to revert
def reverse_migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PythonModule = apps.get_model("api_app", "PythonModule")

    try:
        pm = PythonModule.objects.get(module="PhishStats")
    except PythonModule.DoesNotExist:
        return

    try:
        Parameter.objects.get(name="url", python_module=pm).delete()
    except Parameter.DoesNotExist:
        pass


class Migration(migrations.Migration):

    dependencies = [
        ("analyzers_manager", "0173_replace_dns0_with_dns4eu"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
