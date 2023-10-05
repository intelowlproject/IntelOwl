from django.core.exceptions import ValidationError
from django.db.models.signals import m2m_changed, pre_save
from django.dispatch import receiver

from api_app.pivots_manager.models import PivotConfig


@receiver(pre_save, sender=PivotConfig)
def pre_save_pivot_config(
    sender, instance: PivotConfig, raw, using, update_fields, *args, **kwargs
):
    try:
        instance.description = (
            f"Pivot that executes playbook {instance.playbook_to_execute.name}"
        )
    except AttributeError:
        # this happens when
        # an integrity error will be raised because some fields are missing
        pass
    return instance


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
        plugins_name = ", ".join(
            [instance.related_configs.all().values_list("name", flat=True)]
        )
        instance.description = (
            f"Pivot object for plugins {plugins_name}"
            " that executes"
            f" playbook {instance.playbook_to_execute.name}"
        )


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
        plugins_name = ", ".join(
            [instance.related_configs.all().values_list("name", flat=True)]
        )
        instance.description = (
            f"Pivot object for plugins {plugins_name}"
            " that executes"
            f" playbook {instance.playbook_to_execute.name}"
        )
