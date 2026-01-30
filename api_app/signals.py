# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from typing import Type

from django import dispatch
from django.conf import settings
from django.contrib.admin.models import LogEntry
from django.db import models
from django.dispatch import receiver

from api_app.decorators import prevent_signal_recursion
from api_app.investigations_manager.models import Investigation
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


@receiver(models.signals.post_save, sender=Job)
@prevent_signal_recursion
def post_save_job(sender, instance: Job, *args, **kwargs):
    """
    Signal receiver for the post_save signal of the Job model.
    Calculates and sets the process time if the job has finished analysis time.

    Args:
        sender (Model): The model class sending the signal.
        instance (Job): The instance of the model being saved.
        *args: Additional positional arguments.
        **kwargs: Additional keyword arguments.
    """
    if instance.finished_analysis_time and instance.received_request_time:
        td = instance.finished_analysis_time - instance.received_request_time
        instance.process_time = round(td.total_seconds(), 2)


@receiver(models.signals.post_delete, sender=Job)
def post_delete_job(sender, instance: Job, **kwargs):
    """
    Signal receiver for the post_delete signal of the Job model.
    Deletes the associated investigation if no other jobs are linked to it.

    Args:
        sender (Model): The model class sending the signal.
        instance (Job): The instance of the model being deleted.
        **kwargs: Additional keyword arguments.
    """
    # Try/catch is needed for multiple delete of jobs in the same investigation
    # because the signals is called _after_ every deletion
    try:
        if instance.investigation_id and instance.investigation.jobs.count() == 0:
            instance.investigation.delete()
    except Investigation.DoesNotExist:
        pass


@receiver(migrate_finished)
def post_migrate_api_app(
    sender,
    *args,
    check_unapplied: bool = False,
    **kwargs,
):
    """
    Signal receiver for the custom migrate_finished signal.
    Sets up periodic tasks for health checks and updates based on module configuration.

    Args:
        sender: The sender of the signal.
        *args: Additional positional arguments.
        check_unapplied (bool, optional): If true, does not proceed with setting up tasks. Defaults to False.
        **kwargs: Additional keyword arguments.
    """
    logger.info(f"Post migrate {args} {kwargs}")
    if check_unapplied:
        return
    from django_celery_beat.models import PeriodicTask

    from intel_owl.tasks import update

    for module in PythonModule.objects.filter(health_check_schedule__isnull=False):
        for config in module.configs.filter(health_check_task__isnull=True):
            config.generate_health_check_periodic_task()
    for module in PythonModule.objects.filter(update_schedule__isnull=False, update_task__isnull=True):
        module.generate_update_periodic_task()

    for task in PeriodicTask.objects.filter(enabled=True, task=f"{update.__module__}.{update.__name__}"):
        task.enabled &= settings.REPO_DOWNLOADER_ENABLED
        task.save()


@receiver(models.signals.post_save, sender=PluginConfig)
def post_save_plugin_config(sender, instance: PluginConfig, *args, **kwargs):
    """
    Signal receiver for the post_save signal of the PluginConfig model.
    Refreshes cache keys associated with the PluginConfig instance.

    Args:
        sender (Model): The model class sending the signal.
        instance (PluginConfig): The instance of the model being saved.
        *args: Additional positional arguments.
        **kwargs: Additional keyword arguments.
    """
    instance.refresh_cache_keys()


@receiver(models.signals.post_delete, sender=PluginConfig)
def post_delete_plugin_config(sender, instance: PluginConfig, *args, **kwargs):
    """
    Signal receiver for the post_delete signal of the PluginConfig model.
    Refreshes cache keys associated with the PluginConfig instance after deletion.

    Args:
        sender (Model): The model class sending the signal.
        instance (PluginConfig): The instance of the model being deleted.
        *args: Additional positional arguments.
        **kwargs: Additional keyword arguments.
    """
    instance.refresh_cache_keys()


@receiver(models.signals.post_save, sender=Parameter)
def post_save_parameter(sender, instance: Parameter, *args, **kwargs):
    """
    Signal receiver for the post_save signal of the Parameter model.
    Deletes the list view cache associated with the Parameter instance.

    Args:
        sender (Model): The model class sending the signal.
        instance (Parameter): The instance of the model being saved.
        *args: Additional positional arguments.
        **kwargs: Additional keyword arguments.
    """
    # delete list view cache
    instance.refresh_cache_keys()


@receiver(models.signals.post_delete, sender=Parameter)
def post_delete_parameter(sender, instance: Parameter, *args, **kwargs):
    """
    Signal receiver for the post_delete signal of the Parameter model.
    Deletes the list view cache associated with the Parameter instance after deletion.

    Args:
        sender (Model): The model class sending the signal.
        instance (Parameter): The instance of the model being deleted.
        *args: Additional positional arguments.
        **kwargs: Additional keyword arguments.
    """
    # delete list view cache
    instance.refresh_cache_keys()


@receiver(models.signals.post_save, sender=PythonModule)
def post_save_python_module_periodic_tasks(
    sender: Type[PythonModule], instance: PythonModule, *args, **kwargs
):
    """
    Signal receiver for the post_save signal of the PythonModule model.
    Generates periodic tasks for updates and health checks based on module configurations.

    Args:
        sender (Type[PythonModule]): The model class sending the signal.
        instance (PythonModule): The instance of the model being saved.
        *args: Additional positional arguments.
        **kwargs: Additional keyword arguments.
    """
    instance.generate_update_periodic_task()
    for config in instance.configs.all():
        config.generate_health_check_periodic_task()


@receiver(models.signals.post_delete, sender=PythonModule)
def post_delete_python_module_periodic_tasks(
    sender: Type[PythonModule], instance: PythonModule, using, origin, *args, **kwargs
):
    """
    Signal receiver for the post_delete signal of the PythonModule model.
    Deletes associated update tasks after the module is deleted.

    Args:
        sender (Type[PythonModule]): The model class sending the signal.
        instance (PythonModule): The instance of the model being deleted.
        using: The database alias being used.
        origin: The origin of the delete signal.
        *args: Additional positional arguments.
        **kwargs: Additional keyword arguments.
    """
    if hasattr(instance, "update_task") and instance.update_task:
        instance.update_task.delete()


@receiver(models.signals.post_delete)
def post_delete_python_config_periodic_tasks(
    sender: Type[PythonConfig], instance: PythonConfig, using, origin, *args, **kwargs
):
    """
    Signal receiver for the post_delete signal of the PythonConfig model.
    Deletes associated health check tasks after the PythonConfig instance is deleted.

    Args:
        sender (Type[PythonConfig]): The model class sending the signal.
        instance (PythonConfig): The instance of the model being deleted.
        using: The database alias being used.
        origin: The origin of the delete signal.
        *args: Additional positional arguments.
        **kwargs: Additional keyword arguments.
    """
    if (
        issubclass(sender, PythonConfig)
        and hasattr(instance, "health_check_task")
        and instance.health_check_task
    ):
        instance.health_check_task.delete()


@receiver(models.signals.post_save)
def post_save_python_config_cache(sender, instance, *args, **kwargs):
    """
    Signal receiver for the post_save signal.
    Deletes class cache keys for instances of ListCachable models.
    Refreshes cache keys associated with the PythonConfig instance.

    Args:
        sender (Model): The model class sending the signal.
        instance: The instance of the model being saved.
        *args: Additional positional arguments.
        **kwargs: Additional keyword arguments.
    """
    if issubclass(sender, ListCachable):
        instance.delete_class_cache_keys()
    if issubclass(sender, PythonConfig):
        instance.refresh_cache_keys()


@receiver(models.signals.post_delete)
def post_delete_python_config_cache(sender, instance, *args, **kwargs):
    """
    Signal receiver for the post_delete signal.
    Deletes class cache keys for instances of ListCachable models after deletion.
    Refreshes cache keys associated with the PythonConfig instance after deletion.

    Args:
        sender (Model): The model class sending the signal.
        instance: The instance of the model being deleted.
        using: The database alias being used.
        origin: The origin of the delete signal.
        *args: Additional positional arguments.
        **kwargs: Additional keyword arguments.
    """
    if issubclass(sender, ListCachable):
        instance.delete_class_cache_keys()
    if issubclass(sender, PythonConfig):
        instance.refresh_cache_keys()


@receiver(models.signals.post_save, sender=LogEntry)
def post_save_log_entry(sender, instance: LogEntry, *args, **kwargs):
    """
    Signal receiver for the post_save signal.
    Add a line of log

    Args:
        sender (Model): The model class sending the signal.
        instance: The instance of the model being saved.
        *args: Additional positional arguments.
        **kwargs: Additional keyword arguments.
    """
    logger.info(str(instance))
