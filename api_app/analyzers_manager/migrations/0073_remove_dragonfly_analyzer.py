from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm = PythonModule.objects.get(
        module="dragonfly.DragonflyEmulation",
        base_path="api_app.analyzers_manager.file_analyzers",
    )
    pm.analyzerconfigs.all().delete()
    pm.delete()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("analyzers_manager", "0072_analyzer_config_tweetfeed"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
