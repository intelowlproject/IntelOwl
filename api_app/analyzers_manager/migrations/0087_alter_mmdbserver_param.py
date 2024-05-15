from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")

    pm = PythonModule.objects.get(
        module="mmdb_server.MmdbServer",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    param = pm.parameters.get(name="base_url")
    param.name = "url"
    param.save()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0086_analyzer_config_blint"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
