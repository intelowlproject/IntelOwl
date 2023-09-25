# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

import django_celery_beat.apps
from django import dispatch
from django.conf import settings
from django.db import models
from django.dispatch import receiver

from api_app.helpers import calculate_md5
from api_app.models import Job, Parameter, PluginConfig

migrate_finished = dispatch.Signal()

logger = logging.getLogger(__name__)


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
