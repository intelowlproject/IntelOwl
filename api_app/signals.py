# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from typing import Type

from django import dispatch
from django.conf import settings
from django.db import models
from django.dispatch import receiver

from api_app.decorators import prevent_signal_recursion
from api_app.helpers import calculate_md5
from api_app.models import (
    Job,
    ListCachable,
    Parameter,
    PluginConfig,
    PythonConfig,
    PythonModule,
)

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


@receiver(models.signals.post_save, sender=Job)
@prevent_signal_recursion
def post_save_job(sender, instance: Job, *args, **kwargs):
    if instance.finished_analysis_time and instance.received_request_time:
        td = instance.finished_analysis_time - instance.received_request_time
        instance.process_time = round(td.total_seconds(), 2)


@receiver(models.signals.pre_delete, sender=Job)
def pre_delete_job(sender, instance: Job, **kwargs):
    if instance.file:
        instance.file.delete()


@receiver(models.signals.post_delete, sender=Job)
def post_delete_job(sender, instance: Job, **kwargs):
    if instance.investigation and instance.investigation.jobs.count() == 0:
        instance.investigation.delete()


@receiver(migrate_finished)
def post_migrate_api_app(
    sender,
    *args,
    check_unapplied: bool = False,
    **kwargs,
):
    logger.info(f"Post migrate {args} {kwargs}")
    if check_unapplied:
        return
    from django_celery_beat.models import PeriodicTask

    from intel_owl.tasks import update

    for module in PythonModule.objects.filter(health_check_schedule__isnull=False):
        for config in module.configs.filter(health_check_task__isnull=True):
            config.generate_health_check_periodic_task()
    for module in PythonModule.objects.filter(
        update_schedule__isnull=False, update_task__isnull=True
    ):
        module.generate_update_periodic_task()

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


@receiver(models.signals.post_save, sender=PythonModule)
def post_save_python_module_periodic_tasks(
    sender: Type[PythonModule], instance: PythonModule, *args, **kwargs
):
    instance.generate_update_periodic_task()
    for config in instance.configs.all():
        config.generate_health_check_periodic_task()


@receiver(models.signals.post_delete, sender=PythonModule)
def post_delete_python_module_periodic_tasks(
    sender: Type[PythonModule], instance: PythonModule, using, origin, *args, **kwargs
):
    if hasattr(instance, "update_task") and instance.update_task:
        instance.update_task.delete()


@receiver(models.signals.post_delete)
def post_delete_python_config_periodic_tasks(
    sender: Type[PythonConfig], instance: PythonConfig, using, origin, *args, **kwargs
):
    if (
        issubclass(sender, PythonConfig)
        and hasattr(instance, "health_check_task")
        and instance.health_check_task
    ):
        instance.health_check_task.delete()


@receiver(models.signals.post_save)
def post_save_python_config_cache(sender, instance, *args, **kwargs):
    if issubclass(sender, ListCachable):
        instance.delete_class_cache_keys()


@receiver(models.signals.post_delete)
def post_delete_python_config_cache(sender, instance, using, origin, *args, **kwargs):
    if issubclass(sender, ListCachable):
        instance.delete_class_cache_keys()
