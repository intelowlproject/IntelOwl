from django.db import migrations


def migrate(apps, schema_editor):
    PivotConfig = apps.get_model("pivots_manager", "PivotConfig")

    pc = PivotConfig.objects.get(
        name="ResubmitDownloadedFile",
    )
    pc.playbook_to_execute = "Sample_Static_Analysis"
    pc.save()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("pivots_manager", "0033_pivot_config_extractedonenotefiles"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
