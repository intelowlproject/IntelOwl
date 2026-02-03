import json
import logging
import uuid

from django.conf import settings
from django.db.models.signals import post_delete, pre_save
from django.dispatch import receiver
from django_celery_beat.models import PeriodicTask

from api_app.ingestors_manager.models import IngestorConfig
from api_app.signals import migrate_finished
from authentication.models import UserProfile
from certego_saas.apps.user.models import User
from intel_owl.celery import get_queue_name

logger = logging.getLogger(__name__)


@receiver(pre_save, sender=IngestorConfig)
def pre_save_ingestor_config(sender, instance: IngestorConfig, *args, **kwargs):
    from intel_owl.tasks import execute_ingestor

    user = User.objects.get_or_create(
        username__iexact=f"{instance.name}Ingestor",
        defaults={
            "username": f"{instance.name}Ingestor",
        },
    )[0]

    # in case the user has been created
    if not hasattr(user, "profile"):
        user.profile = UserProfile()

    user.profile.task_priority = 7
    user.profile.is_robot = True
    user.profile.save()
    instance.user = user

    periodic_task = PeriodicTask.objects.update_or_create(
        name__iexact=f"{instance.name}Ingestor",
        task=f"{execute_ingestor.__module__}.{execute_ingestor.__name__}",
        defaults={
            "name": f"{instance.name}Ingestor",
            "crontab": instance.schedule,
            "queue": instance.queue,
            "kwargs": json.dumps({"config_name": instance.name}),
            "enabled": not instance.disabled,
        },
    )[0]
    instance.periodic_task = periodic_task
    return instance


@receiver(post_delete, sender=IngestorConfig)
def post_delete_ingestor_config(sender, instance: IngestorConfig, using, origin, *args, **kwargs):
    instance.periodic_task.delete()
    instance.user.delete()


@receiver(migrate_finished)
def post_migrate_ingestors_manager(
    sender,
    *args,
    check_unapplied: bool = False,
    **kwargs,
):
    logger.info(f"Post migrate {args} {kwargs}")
    if check_unapplied:
        return
    from intel_owl.tasks import refresh_cache

    refresh_cache.apply_async(
        queue=get_queue_name(settings.CONFIG_QUEUE),
        MessageGroupId=str(uuid.uuid4()),
        priority=3,
        args=[IngestorConfig.python_path],
    )
