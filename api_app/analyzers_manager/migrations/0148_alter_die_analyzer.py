from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")

    pm = PythonModule.objects.get(
        module="detectiteasy.DetectItEasy",
        base_path="api_app.analyzers_manager.file_analyzers",
    )
    pm.parameters.all().delete()

    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    ac = AnalyzerConfig.objects.get(
        name="DetectItEasy",
    )
    ac.docker_based = False
    ac.save()


def reverse_migrate(apps, schema_editor): ...


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0065_job_mpnodesearch"),
        (
            "analyzers_manager",
            "0147_alter_analyzer_config_feodo_yaraify_urlhaus_yaraify_scan",
        ),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
