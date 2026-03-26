# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.db import migrations


def _cleanup_schedule(schedule, field_name, PeriodicTask, PythonModule, is_crontab):
    """Delete a schedule if it is no longer referenced by any task or module."""
    if schedule is None:
        return
    still_used = PeriodicTask.objects.filter(**{field_name: schedule}).exists()
    if not still_used and is_crontab:
        still_used = (
            PythonModule.objects.filter(update_schedule=schedule).exists()
            or PythonModule.objects.filter(health_check_schedule=schedule).exists()
        )
    if not still_used:
        try:
            schedule.delete()
        except Exception:
            pass  # Another model (e.g. IngestorConfig) may still reference this schedule


def remove_talos_forward(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    PythonModule = apps.get_model("api_app", "PythonModule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    CrontabSchedule = apps.get_model("django_celery_beat", "CrontabSchedule")
    SolarSchedule = apps.get_model("django_celery_beat", "SolarSchedule")
    ClockedSchedule = apps.get_model("django_celery_beat", "ClockedSchedule")

    # Identify Talos PythonModule instances first
    module_qs = PythonModule.objects.filter(
        module="talos.Talos",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )

    # Remove all analyzer configs referencing these modules
    AnalyzerConfig.objects.filter(python_module__in=module_qs).delete()

    for module in module_qs:
        update_task_id = getattr(module, "update_task_id", None)
        if update_task_id is not None:
            try:
                task = PeriodicTask.objects.get(id=update_task_id)
            except PeriodicTask.DoesNotExist:
                task = None
            if task is not None:
                schedule_data = (
                    ("interval", IntervalSchedule, task.interval),
                    ("crontab", CrontabSchedule, task.crontab),
                    ("solar", SolarSchedule, task.solar),
                    ("clocked", ClockedSchedule, task.clocked),
                )
                task.delete()
                for field_name, schedule_model, schedule in schedule_data:
                    _cleanup_schedule(
                        schedule,
                        field_name,
                        PeriodicTask,
                        PythonModule,
                        is_crontab=(schedule_model is CrontabSchedule),
                    )
        # Capture modules own schedule before deletion
        module_schedules = [
            getattr(module, attr, None)
            for attr in ("update_schedule", "health_check_schedule")
        ]
        module.delete()
        # Clean up orphaned CrontabSchedules from the module
        for sched in module_schedules:
            _cleanup_schedule(sched, "crontab", PeriodicTask, PythonModule, is_crontab=True)


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0179_add_local_db_models_tor_danmeuk"),
    ]

    operations = [
        migrations.RunPython(
            remove_talos_forward, reverse_code=migrations.RunPython.noop
        ),
    ]
