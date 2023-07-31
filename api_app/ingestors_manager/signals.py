import json

from django.db.models.signals import post_delete, pre_save
from django.dispatch import receiver
from django_celery_beat.models import PeriodicTask

from api_app.ingestors_manager.models import IngestorConfig
from certego_saas.apps.user.models import User


@receiver(pre_save, sender=IngestorConfig)
def pre_save_ingestor_config(sender, instance: IngestorConfig, *args, **kwargs):
    if not hasattr(instance, "user") or not instance.user:
        instance.user = User.objects.create(username=f"Ingestor{instance.name.title()}")
    if not hasattr(instance, "periodic_task") or not instance.periodic_task:
        periodic_task = PeriodicTask(
            crontab=instance.schedule,
            name=f"{instance.name}PeriodicTask",
            task="intel_owl.tasks.execute_ingestor",
            kwargs=json.dumps({"config_pk": instance.pk}),
            queue=instance.config["queue"],
            enabled=False,
        )
        periodic_task.full_clean()
        periodic_task.save()
        instance.periodic_task = periodic_task
    return instance


@receiver(post_delete, sender=IngestorConfig)
def post_delete_ingestor_config(
    sender, instance: IngestorConfig, using, origin, *args, **kwargs
):
    instance.periodic_task.delete()
    instance.user.delete()
