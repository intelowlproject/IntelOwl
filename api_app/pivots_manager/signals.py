from django.core.exceptions import ValidationError
from django.db.models.signals import m2m_changed, post_delete, post_migrate, post_save, pre_save
from django.dispatch import receiver

from api_app.pivots_manager.apps import PivotsManagerConfig
from api_app.pivots_manager.models import PivotConfig


@receiver(pre_save, sender=PivotConfig)
def pre_save_pivot_config(
    sender, instance: PivotConfig, raw, using, update_fields, *args, **kwargs
):
    try:
        if instance.pk:
            instance.description = instance._generate_full_description()
        else:
            instance.description = (
                f"Pivot that executes playbook {instance.playbook_to_execute.name}"
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

        
@receiver(m2m_changed, sender=PivotConfig.related_analyzer_configs.through)
def m2m_changed_pivot_config_analyzer_config(
    sender,
    instance: PivotConfig,
    action: str,
    reverse,
    model,
    pk_set,
    using,
    *args,
    **kwargs,
):
    if action == "pre_add" and instance.related_connector_configs.exists():
        raise ValidationError(
            "You can't set both analyzers and connectors configs to a pivot"
        )
    if action.startswith("post"):
        instance.description = instance._generate_full_description()
        instance.save()


@receiver(m2m_changed, sender=PivotConfig.related_connector_configs.through)
def m2m_changed_pivot_config_connector_config(
    sender,
    instance: PivotConfig,
    action: str,
    reverse,
    model,
    pk_set,
    using,
    *args,
    **kwargs,
):
    if action == "pre_add" and instance.related_analyzer_configs.exists():
        raise ValidationError(
            "You can't set both analyzers and connectors configs to a pivot"
        )
    if action.startswith("post"):
        instance.description = instance._generate_full_description()
        instance.save()
