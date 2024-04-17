from django.db import migrations


def migrate_python_module_pivot(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm, _ = PythonModule.objects.update_or_create(
        module="compare.Compare",
        base_path="api_app.pivots_manager.pivots",
    )
    Parameter = apps.get_model("api_app", "Parameter")
    Parameter.objects.get_or_create(
        name="field_to_compare",
        type="str",
        python_module=pm,
        is_secret=False,
        required=True,
        defaults={
            "description": "Dotted path to the field",
        },
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
        ("pivots_manager", "0002_000_self_analyzable"),
    ]
    operations = [
        migrations.RunPython(migrate_python_module_pivot, reverse_migrate_module_pivot)
    ]
