from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    feodo_tracker_module = PythonModule.objects.get(
        module="feodo_tracker.Feodo_Tracker",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )

    AnalyzerConfig.objects.filter(python_module=feodo_tracker_module).update(
        disabled=True
    )


def reverse_migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    feodo_tracker_module = PythonModule.objects.get(
        module="feodo_tracker.Feodo_Tracker",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )

    AnalyzerConfig.objects.filter(python_module=feodo_tracker_module).update(
        disabled=False
    )


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0062_alter_parameter_type"),
        ("analyzers_manager", "0175_analyzer_config_cleanbrowsing_malicious_detector"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
