from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    CrontabSchedule = apps.get_model("django_celery_beat", "CrontabSchedule")

    cron_firehol = CrontabSchedule.objects.get_or_create(minute=10, hour=18)[0]
    cron_tranco = CrontabSchedule.objects.get_or_create(minute=0, hour=1)[0]
    pm_firehol = PythonModule.objects.get(
        module="firehol_iplist.FireHol_IPList",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    pm_tranco = PythonModule.objects.get(
        module="tranco.Tranco",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    pm_firehol.update_schedule = cron_firehol
    pm_tranco.update_schedule = cron_tranco
    pm_firehol.save()
    pm_tranco.save()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0071_delete_last_elastic_report"),
        ("analyzers_manager", "0153_remove_firehol_iplist_list_name_parameter"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
