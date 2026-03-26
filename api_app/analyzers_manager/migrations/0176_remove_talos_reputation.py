# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.db import migrations


def remove_talos_forward(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    PythonModule = apps.get_model("api_app", "PythonModule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    CrontabSchedule = apps.get_model("django_celery_beat", "CrontabSchedule")
    SolarSchedule = apps.get_model("django_celery_beat", "SolarSchedule")
    ClockedSchedule = apps.get_model("django_celery_beat", "ClockedSchedule")

    # Identify the Talos PythonModule instances first
    module_qs = PythonModule.objects.filter(
        module="talos.Talos",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )

    # Remove ALL analyzer configs referencing these modules (includes clones)
    AnalyzerConfig.objects.filter(python_module__in=module_qs).delete()

    for module in module_qs:
        update_task_id = getattr(module, "update_task_id", None)
        if update_task_id is not None:
            try:
                task = PeriodicTask.objects.get(id=update_task_id)
            except PeriodicTask.DoesNotExist:
                task = None
            if task is not None:
                # Capture schedules
                interval = task.interval
                crontab = task.crontab
                solar = task.solar
                clocked = task.clocked
                task.delete()
                # Clean up schedules which are no more referenced
                schedule_data = (
                    ("interval", IntervalSchedule, interval),
                    ("crontab", CrontabSchedule, crontab),
                    ("solar", SolarSchedule, solar),
                    ("clocked", ClockedSchedule, clocked),
                )
                for field_name, schedule_model, schedule in schedule_data:
                    if schedule is not None:
                        still_used = PeriodicTask.objects.filter(
                            **{field_name: schedule}
                        ).exists()
                        if not still_used and schedule_model is CrontabSchedule:
                            still_used = (
                                PythonModule.objects.filter(
                                    update_schedule=schedule
                                ).exists()
                                or PythonModule.objects.filter(
                                    health_check_schedule=schedule
                                ).exists()
                            )
                        if not still_used:
                            schedule.delete()
        # Capture modules own schedules before deletion
        module_schedules = []
        for attr in ("update_schedule", "health_check_schedule"):
            sched = getattr(module, attr, None)
            if sched is not None:
                module_schedules.append(sched)
        module.delete()
        # Clean up orphaned CrontabSchedules from the module
        for sched in module_schedules:
            if not PeriodicTask.objects.filter(crontab=sched).exists():
                if not PythonModule.objects.filter(update_schedule=sched).exists():
                    if not PythonModule.objects.filter(health_check_schedule=sched).exists():
                        sched.delete()


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0176_analyzer_config_macho_info"),
    ]

    operations = [
        migrations.RunPython(
            remove_talos_forward, reverse_code=migrations.RunPython.noop
        ),
    ]
