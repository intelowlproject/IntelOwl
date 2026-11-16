# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations

REMOVED_MODULES = ["spyse.Spyse", "crxcavator.CRXcavator"]


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    OrganizationPluginConfiguration = apps.get_model("api_app", "OrganizationPluginConfiguration")
    ContentType = apps.get_model("contenttypes", "ContentType")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    content_type = ContentType.objects.filter(app_label="analyzers_manager", model="analyzerconfig").first()
    for pm in PythonModule.objects.filter(
        module__in=REMOVED_MODULES,
        base_path="api_app.analyzers_manager.observable_analyzers",
    ):
        configs = pm.analyzerconfigs.all()
        task_ids = [pm.update_task_id]
        task_ids.extend(configs.values_list("health_check_task_id", flat=True))
        if content_type:
            org_configs = OrganizationPluginConfiguration.objects.filter(
                content_type=content_type,
                object_id__in=list(configs.values_list("pk", flat=True)),
            )
            task_ids.extend(org_configs.values_list("rate_limit_enable_task_id", flat=True))
            org_configs.delete()
        PeriodicTask.objects.filter(id__in=[t for t in task_ids if t]).delete()
        configs.delete()
        pm.delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("analyzers_manager", "0204_analyzer_config_netapi"),
        ("contenttypes", "0002_remove_content_type_name"),
        ("django_celery_beat", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(migrate, migrations.RunPython.noop),
    ]
