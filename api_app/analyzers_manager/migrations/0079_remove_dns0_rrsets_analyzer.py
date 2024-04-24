from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm = PythonModule.objects.filter(
        module="dns0.dns0_rrsets.DNS0Rrsets",
        base_path="api_app.analyzers_manager.observable_analyzers",
    ).first()
    if pm:
        pm.analyzerconfigs.all().delete()
        pm.delete()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("playbooks_manager", "0032_delete_dns0_playbook_free_to_use_analyzers"),
        ("analyzers_manager", "0078_analyzer_config_hfinger"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
