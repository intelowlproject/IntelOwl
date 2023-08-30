# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
import uuid

import django_celery_beat.apps
from django import dispatch
from django.conf import settings
from django.core.cache import cache
from django.db import ProgrammingError, models
from django.dispatch import receiver

from api_app.helpers import calculate_md5
from api_app.models import Job, Parameter, PluginConfig

migrate_finished = dispatch.Signal()

logger = logging.getLogger(__name__)


@receiver(migrate_finished)
def post_migrate_finished(*args, **kwargs):
    """
    This is executed after all migrations are done
    """
    logger.info("Cleaning cache")
    try:
        cache.clear()
    except ProgrammingError:
        logger.info("No table to clean")
    finally:

        from certego_saas.models import User
        from intel_owl.celery import DEFAULT_QUEUE
        from intel_owl.tasks import create_caches

        # we are removing system users
        for user in User.objects.exclude(email=""):
            logger.info(f"Creating cache for user {user.username}")
            create_caches.apply_async(
                routing_key=DEFAULT_QUEUE,
                MessageGroupId=str(uuid.uuid4()),
                args=[user.pk],
            )


@receiver(models.signals.pre_save, sender=Job)
def pre_save_job(sender, instance: Job, **kwargs):
    if not instance.md5:
        instance.md5 = calculate_md5(
            instance.file.read()
            if instance.is_sample
            else instance.observable_name.encode("utf-8")
        )


@receiver(models.signals.pre_delete, sender=Job)
def pre_delete_job(sender, instance: Job, **kwargs):
    if instance.file:
        instance.file.delete()


@receiver(models.signals.post_migrate, sender=django_celery_beat.apps.BeatConfig)
def post_migrate_beat(
    sender, app_config, verbosity, interactive, stdout, using, plan, apps, **kwargs
):
    from django_celery_beat.models import PeriodicTask

    for task in PeriodicTask.objects.filter(
        enabled=True, task="intel_owl.tasks.update"
    ):
        task.enabled &= settings.REPO_DOWNLOADER_ENABLED
        task.save()


@receiver(models.signals.post_save, sender=PluginConfig)
def post_save_plugin_config(sender, instance: PluginConfig, *args, **kwargs):
    instance.refresh_cache_keys()


@receiver(models.signals.post_delete, sender=PluginConfig)
def post_delete_plugin_config(sender, instance: PluginConfig, *args, **kwargs):
    instance.refresh_cache_keys()


@receiver(models.signals.post_save, sender=Parameter)
def post_save_parameter(sender, instance: Parameter, *args, **kwargs):
    # delete list view cache
    instance.refresh_cache_keys()


@receiver(models.signals.post_delete, sender=Parameter)
def post_delete_parameter(sender, instance: Parameter, *args, **kwargs):
    # delete list view cache
    instance.refresh_cache_keys()
