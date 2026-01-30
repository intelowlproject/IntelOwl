import logging
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db.models.signals import m2m_changed, pre_save
from django.dispatch import receiver

from api_app.pivots_manager.models import PivotConfig
from api_app.signals import migrate_finished
from intel_owl.celery import get_queue_name

logger = logging.getLogger(__name__)


@receiver(migrate_finished)
def post_migrate_pivots_manager(
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
        args=[PivotConfig.python_path],
    )


@receiver(pre_save, sender=PivotConfig)
def pre_save_pivot_config(sender, instance: PivotConfig, raw, using, update_fields, *args, **kwargs):
    try:
        if instance.pk:
            instance.description = instance._generate_full_description()
        else:
            instance.description = f"Pivot that executes playbook {instance.playbook_to_execute.name}"
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
        raise ValidationError("You can't set both analyzers and connectors configs to a pivot")
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
        raise ValidationError("You can't set both analyzers and connectors configs to a pivot")
    if action.startswith("post"):
        instance.description = instance._generate_full_description()
        instance.save()


@receiver(m2m_changed, sender=PivotConfig.playbooks_choice.through)
def m2m_changed_pivot_config_playbooks_choice(
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
    if action.startswith("post"):
        instance.description = instance._generate_full_description()
        instance.save()
