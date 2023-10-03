import json

from django.conf import settings
from django.db.models.signals import post_delete, post_migrate, post_save, pre_save
from django.dispatch import receiver
from django_celery_beat.models import PeriodicTask

from api_app.analyzers_manager.apps import AnalyzersManagerConfig
from api_app.analyzers_manager.models import AnalyzerConfig


@receiver(pre_save, sender=AnalyzerConfig)
def pre_save_analyzer_config(sender, instance: AnalyzerConfig, *args, **kwargs):
    if (
        hasattr(instance.python_module.python_class, "_update")
        and callable(instance.python_module.python_class._update)
        and hasattr(instance, "update_schedule")
        and instance.update_schedule
    ):
        periodic_task = PeriodicTask.objects.update_or_create(
            name=f"{instance.name.title()}Analyzer",
            task="intel_owl.tasks.update",
            defaults={
                "crontab": instance.update_schedule,
                "queue": instance.queue,
                "enabled": not instance.disabled and settings.REPO_DOWNLOADER_ENABLED,
                "kwargs": json.dumps({"python_module_pk": instance.python_module_id}),
            },
        )[0]
        instance.update_task = periodic_task
    return instance


@receiver(post_save, sender=AnalyzerConfig)
def post_save_analyzer_config(sender, instance: AnalyzerConfig, *args, **kwargs):
    # delete list view cache
    instance.delete_class_cache_keys()


@receiver(post_delete, sender=AnalyzerConfig)
def post_delete_analyzer_config(
    sender, instance: AnalyzerConfig, using, origin, *args, **kwargs
):
    # delete list view cache
    instance.delete_class_cache_keys()

    if hasattr(instance, "periodic_task") and instance.periodic_task:
        instance.periodic_task.delete()


@receiver(post_migrate, sender=AnalyzersManagerConfig)
def post_migrate_analyzer(
    sender, app_config, verbosity, interactive, stdout, using, plan, apps, **kwargs
):
    if plan:
        AnalyzerConfig.delete_class_cache_keys()
