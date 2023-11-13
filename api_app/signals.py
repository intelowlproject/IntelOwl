# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from typing import Type

import django_celery_beat.apps
from django import dispatch
from django.conf import settings
from django.db import models
from django.dispatch import receiver

from api_app.helpers import calculate_md5
from api_app.models import Job, Parameter, PluginConfig, PythonConfig

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

    from intel_owl.tasks import update

    for task in PeriodicTask.objects.filter(
        enabled=True, task=f"{update.__module__}.{update.__name__}"
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


@receiver(models.signals.pre_save)
def pre_save_python_config_periodic_tasks(
    sender: Type[PythonConfig], instance: PythonConfig, *args, **kwargs
):
    if issubclass(sender, PythonConfig):
        instance.generate_health_check_periodic_task()
        instance.generate_update_periodic_task()


@receiver(models.signals.post_delete)
def post_delete_python_config_periodic_tasks(
    sender: Type[PythonConfig], instance: PythonConfig, using, origin, *args, **kwargs
):
    if issubclass(sender, PythonConfig):
        if hasattr(instance, "health_check_task") and instance.health_check_task:
            instance.health_check_task.delete()

        if hasattr(instance, "update_task") and instance.update_task:
            instance.update_task.delete()


@receiver(models.signals.post_save)
def post_save_python_config_cache(sender, instance: PythonConfig, *args, **kwargs):
    if issubclass(sender, PythonConfig):
        instance.delete_class_cache_keys()


@receiver(models.signals.post_delete)
def post_delete_python_config_cache(
    sender, instance: PythonConfig, using, origin, *args, **kwargs
):
    if issubclass(sender, PythonConfig):
        instance.delete_class_cache_keys()
