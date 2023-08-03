import json

from django.db.models.signals import post_delete, pre_save
from django.dispatch import receiver
from django_celery_beat.models import PeriodicTask

from api_app.ingestors_manager.models import IngestorConfig
from certego_saas.apps.user.models import User


@receiver(pre_save, sender=IngestorConfig)
def pre_save_ingestor_config(sender, instance: IngestorConfig, *args, **kwargs):
    instance.user = User.objects.get_or_create(
        username=f"Ingestor{instance.name.title()}"
    )[0]

    periodic_task = PeriodicTask.objects.update_or_create(
        name=f"{instance.name}PeriodicTask",
        task="intel_owl.tasks.execute_ingestor",
        defaults={
            "crontab": instance.schedule,
            "queue": instance.queue,
            "kwargs": json.dumps({"config_pk": instance.pk}),
        },
    )[0]
    if not hasattr(instance, "periodic_task") or not instance.periodic_task:
        periodic_task.enabled = False
        periodic_task.save()
    instance.periodic_task = periodic_task
    return instance


@receiver(post_delete, sender=IngestorConfig)
def post_delete_ingestor_config(
    sender, instance: IngestorConfig, using, origin, *args, **kwargs
):
    instance.periodic_task.delete()
    instance.user.delete()
