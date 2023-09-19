import json

from django.db import migrations

from intel_owl.celery import get_queue_name


def _create_periodic_task(PeriodicTask, analyzer, crontab):
    pt = PeriodicTask.objects.create(
        name=f"{analyzer.name.title()}Analyzer",
        task="intel_owl.tasks.update",
        crontab=crontab,
        queue=get_queue_name(analyzer.config["queue"]),
        enabled=not analyzer.disabled,
        kwargs=json.dumps({"python_module_pk": analyzer.python_module}),
    )
    analyzer.update_schedule = crontab
    analyzer.update_task = pt
    analyzer.save()


def migrate_config(apps, schema_editor):
    CrontabSchedule = apps.get_model("django_celery_beat", "CrontabSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    maxmind = AnalyzerConfig.objects.get(python_module="maxmind.Maxmind")
    c1 = CrontabSchedule.objects.get_or_create(minute=0, hour=1, day_of_week=3)[0]
    _create_periodic_task(PeriodicTask, maxmind, c1)
    c2 = CrontabSchedule.objects.get_or_create(minute=5, hour="*/6")[0]
    phishing_army = AnalyzerConfig.objects.get(
        python_module="phishing_army.PhishingArmy"
    )
    _create_periodic_task(PeriodicTask, phishing_army, c2)

    c3 = CrontabSchedule.objects.get_or_create(minute=10, hour="*/6")[0]
    talos = AnalyzerConfig.objects.get(python_module="talos.Talos")
    _create_periodic_task(PeriodicTask, talos, c3)

    c4 = CrontabSchedule.objects.get_or_create(minute="*/10")[0]
    tor = AnalyzerConfig.objects.get(python_module="tor.Tor")
    _create_periodic_task(PeriodicTask, tor, c4)

    c5 = CrontabSchedule.objects.get_or_create(minute=0, hour=0)[0]
    yara = AnalyzerConfig.objects.get(python_module="yara_scan.YaraScan")
    _create_periodic_task(PeriodicTask, yara, c5)

    c6 = CrontabSchedule.objects.get_or_create(minute=0, hour=0, day_of_week="2,5")[0]
    quark = AnalyzerConfig.objects.get(python_module="quark_engine.QuarkEngine")
    _create_periodic_task(PeriodicTask, quark, c6)


def reverse_migrate_config(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    maxmind = AnalyzerConfig.objects.get(python_module="maxmind.Maxmind")
    maxmind.update_task.delete()
    phishing_army = AnalyzerConfig.objects.get(
        python_module="phishing_army.PhishingArmy"
    )
    phishing_army.update_task.delete()
    talos = AnalyzerConfig.objects.get(python_module="talos.Talos")
    talos.update_task.delete()
    tor = AnalyzerConfig.objects.get(python_module="tor.Tor")
    tor.update_task.delete()
    yara = AnalyzerConfig.objects.get(python_module="yara_scan.YaraScan")
    yara.update_task.delete()
    quark = AnalyzerConfig.objects.get(python_module="quark_engine.QuarkEngine")
    quark.update_task.delete()


def migrate_generic_tasks(apps, schema_editor):
    CrontabSchedule = apps.get_model("django_celery_beat", "CrontabSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    # notification

    c1 = CrontabSchedule.objects.get_or_create(minute=0, hour=22)[0]
    PeriodicTask.objects.create(
        name="update_notifications_with_releases",
        task="intel_owl.tasks.update_notifications_with_releases",
        crontab=c1,
        enabled=True,
        queue=get_queue_name("default"),
    )
    # check_stuck_analysis
    c2 = CrontabSchedule.objects.get_or_create(minute="*/5")[0]
    PeriodicTask.objects.create(
        name="check_stuck_analysis",
        task="intel_owl.tasks.check_stuck_analysis",
        crontab=c2,
        enabled=True,
        queue=get_queue_name("default"),
        kwargs=json.dumps({"check_pending": True}),
    )
    # remove_old_jobs
    c3 = CrontabSchedule.objects.get_or_create(minute=10, hour=2)[0]
    PeriodicTask.objects.create(
        name="remove_old_jobs",
        task="intel_owl.tasks.remove_old_jobs",
        crontab=c3,
        enabled=True,
        queue=get_queue_name("default"),
    )


def reverse_migrate_generic_tasks(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTask.objects.get(name="remove_old_jobs").delete()
    PeriodicTask.objects.get(name="check_stuck_analysis").delete()
    PeriodicTask.objects.get(name="update_notifications_with_releases").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("django_celery_beat", "0018_improve_crontab_helptext"),
        ("analyzers_manager", "0033_analyzerconfig_update_schedule_and_more"),
    ]

    operations = [
        migrations.RunPython(migrate_config, reverse_migrate_config),
        migrations.RunPython(migrate_generic_tasks, reverse_migrate_generic_tasks),
    ]
