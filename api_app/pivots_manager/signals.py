from django.db.models.signals import post_delete, post_migrate, post_save, pre_save
from django.dispatch import receiver

from api_app.pivots_manager.apps import PivotsManagerConfig
from api_app.pivots_manager.models import PivotConfig


@receiver(pre_save, sender=PivotConfig)
def pre_save_pivot_config(
    sender, instance: PivotConfig, raw, using, update_fields, *args, **kwargs
):
    try:
        instance.description = (
            f"Pivot object for plugin {str(instance.related_config.name)}"
            " that executes "
            f" playbook {instance.playbook_to_execute.name}"
        )
    except AttributeError:
        # this happens when
        # an integrity error will be raised because some fields are missing
        pass
    return instance


@receiver(post_save, sender=PivotConfig)
def post_save_pivot_config(sender, instance: PivotConfig, *args, **kwargs):
    instance.delete_class_cache_keys()


@receiver(post_delete, sender=PivotConfig)
def post_delete_pivot_config(
    sender, instance: PivotConfig, using, origin, *args, **kwargs
):
    instance.delete_class_cache_keys()


@receiver(post_migrate, sender=PivotsManagerConfig)
def post_migrate_pivot(
    sender, app_config, verbosity, interactive, stdout, using, plan, apps, **kwargs
):
    if plan:
        PivotConfig.delete_class_cache_keys()
