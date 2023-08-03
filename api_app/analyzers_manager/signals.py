import json

from django.db.models.signals import pre_save
from django.dispatch import receiver
from django_celery_beat.models import PeriodicTask

from api_app.analyzers_manager.models import AnalyzerConfig


@receiver(pre_save, sender=AnalyzerConfig)
def pre_save_analyzer_config(sender, instance: AnalyzerConfig, *args, **kwargs):
    if hasattr(instance.python_class, "_update") and callable(instance.python_class._update):
        if not hasattr(instance, "update_task") or not instance.update_task:
            if hasattr(instance, "update_schedule") and instance.update_schedule:
                periodic_task = PeriodicTask(
                    crontab=instance.update_schedule,
                    name=f"{instance.name}PeriodicTask",
                    task="intel_owl.tasks.update",
                    kwargs=json.dumps({"config_pk": instance.pk}),
                    queue=instance.queue,
                    enabled=not instance.disabled,
                )
                periodic_task.full_clean()
                periodic_task.save()
                instance.update_task = periodic_task
    return instance
