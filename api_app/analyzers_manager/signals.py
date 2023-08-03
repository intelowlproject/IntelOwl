import json

from django.conf import settings
from django.db.models.signals import post_delete, pre_save
from django.dispatch import receiver
from django_celery_beat.models import PeriodicTask

from api_app.analyzers_manager.models import AnalyzerConfig


@receiver(pre_save, sender=AnalyzerConfig)
def pre_save_analyzer_config(sender, instance: AnalyzerConfig, *args, **kwargs):
    if hasattr(instance.python_class, "_update") and callable(
        instance.python_class._update
    ):
        if hasattr(instance, "update_schedule") and instance.update_schedule:
            periodic_task = PeriodicTask.objects.update_or_create(
                name=f"{instance.name}PeriodicTask",
                task="intel_owl.tasks.update",
                defaults={
                    "crontab": instance.update_schedule,
                    "queue": instance.queue,
                    "enabled": not instance.disabled
                    and settings.REPO_DOWNLOADER_ENABLED,
                    "kwargs": json.dumps({"config_pk": instance.pk}),
                },
            )[0]
            instance.update_task = periodic_task
    return instance


@receiver(post_delete, sender=AnalyzerConfig)
def post_delete_analyzer_config(
    sender, instance: AnalyzerConfig, using, origin, *args, **kwargs
):
    if hasattr(instance, "periodic_task") and instance.periodic_task:
        instance.periodic_task.delete()
