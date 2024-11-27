from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    PivotConfig = apps.get_model("pivots_manager", "PivotConfig")
    pivots_to_update = PivotConfig.objects.filter(
        name__in=["ExtractedOneNoteFiles", "ResubmitDownloadedFile"]
    )
    pm = PythonModule.objects.create(
        health_check_schedule=None,
        update_schedule=None,
        module="load_file_same_playbook.LoadFileSamePlaybook",
        base_path="api_app.pivots_manager.pivots",
    )
    param1 = Parameter.objects.create(
        name="field_to_compare",
        type="str",
        description="Dotted path to the field",
        is_secret=False,
        required=True,
        python_module=pm,
    )
    for pivot_to_update in pivots_to_update:

        PluginConfig.objects.filter(pivot_config=pivot_to_update).delete()
        pivot_to_update.python_module = pm
        PluginConfig.objects.create(
            parameter=param1,
            value="stored_base64",
            for_organization=False,
            updated_at="2024-11-07T10:35:46.217160Z",
            analyzer_config=None,
            connector_config=None,
            visualizer_config=None,
            ingestor_config=None,
            pivot_config=pivot_to_update,
        )
        pivot_to_update.full_clean()
        pivot_to_update.save()


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("api_app", "0063_singleton_and_elastic_report"),
        ("pivots_manager", "0035_pivot_config_phishingextractortoanalysis"),
    ]

    operations = [migrations.RunPython(migrate, migrations.RunPython.noop)]
