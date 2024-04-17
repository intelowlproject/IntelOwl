from django.db import migrations


def migrate_python_module_pivot(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    PythonModule.objects.update_or_create(
        module="self_analyzable.SelfAnalyzable",
        base_path="api_app.pivots_manager.pivots",
    )
    PythonModule.objects.create(
        module="base.Base", base_path="api_app.pivots_manager.pivots"
    )


def reverse_migrate_module_pivot(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    PythonModule.objects.get(
        module="self_analyzable.SelfAnalyzable",
        base_path="api_app.pivots_manager.pivots",
    ).delete()
    PythonModule.objects.get(
        module="base.Base", base_path="api_app.pivots_manager.pivots"
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("pivots_manager", "0001_2_initial_squashed"),
    ]
    operations = [
        migrations.RunPython(migrate_python_module_pivot, reverse_migrate_module_pivot)
    ]
