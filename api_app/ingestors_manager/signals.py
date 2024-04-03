import json

from django.db.models.signals import post_delete, post_migrate, pre_save
from django.dispatch import receiver
from django_celery_beat.models import PeriodicTask

from api_app.ingestors_manager.apps import IngestorsManagerConfig
from api_app.ingestors_manager.models import IngestorConfig
from certego_saas.apps.user.models import User


@receiver(pre_save, sender=IngestorConfig)
def pre_save_ingestor_config(sender, instance: IngestorConfig, *args, **kwargs):
    from intel_owl.tasks import execute_ingestor

    instance.user = User.objects.get_or_create(
        username=f"{instance.name.title()}Ingestor"
    )[0]

    periodic_task = PeriodicTask.objects.update_or_create(
        name=f"{instance.name.title()}Ingestor",
        task=f"{execute_ingestor.__module__}.{execute_ingestor.__name__}",
        defaults={
            "crontab": instance.schedule,
            "queue": instance.queue,
            "kwargs": json.dumps({"config_name": instance.name}),
            "enabled": not instance.disabled,
        },
    )[0]
    instance.periodic_task = periodic_task
    return instance


@receiver(post_delete, sender=IngestorConfig)
def post_delete_ingestor_config(
    sender, instance: IngestorConfig, using, origin, *args, **kwargs
):
    instance.periodic_task.delete()
    instance.user.delete()


@receiver(post_migrate, sender=IngestorsManagerConfig)
def post_migrate_ingestor(
    sender, app_config, verbosity, interactive, stdout, using, plan, apps, **kwargs
):
    if plan:
        IngestorConfig.delete_class_cache_keys()
