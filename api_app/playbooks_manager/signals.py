import logging
import uuid
from typing import Type

from django.conf import settings
from django.db.models.signals import m2m_changed
from django.dispatch import receiver
from rest_framework.exceptions import ValidationError

from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.signals import migrate_finished
from intel_owl.celery import get_queue_name

logger = logging.getLogger(__name__)


@receiver(migrate_finished)
def post_migrate_playbooks_manager(
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
        args=[PlaybookConfig.python_path],
    )


@receiver(m2m_changed, sender=PlaybookConfig.analyzers.through)
def m2m_changed_analyzers_playbook_config(
    sender, instance: PlaybookConfig, action, reverse, model, pk_set, *args, **kwargs
):
    if action == "post_add":
        instance.tlp = instance._generate_tlp()
        instance.save()
    return instance


@receiver(m2m_changed, sender=PlaybookConfig.connectors.through)
def m2m_changed_connectors_playbook_config(
    sender, instance: PlaybookConfig, action, reverse, model, pk_set, *args, **kwargs
):
    if action == "post_add":
        instance.tlp = instance._generate_tlp()
        instance.save()
    return instance


@receiver(m2m_changed, sender=PlaybookConfig.pivots.through)
def m2m_changed_pivots_playbook_config(
    sender,
    instance: PlaybookConfig,
    action: str,
    reverse,
    model: Type[PivotConfig],
    pk_set,
    using,
    *args,
    **kwargs,
):
    if action == "pre_add":
        objects = model.objects.filter(pk__in=pk_set)
        valid_pks = objects.valid(instance.analyzers.all(), instance.connectors.all()).values_list(
            "pk", flat=True
        )
        wrong_pivots = objects.exclude(pk__in=valid_pks)
        if wrong_pivots.exists():
            raise ValidationError(
                f"You can't set pivot{'s' if wrong_pivots.size() > 0 else ''}"
                f" {','.join(wrong_pivots.values_list('name', flat=True))} because"
                " the playbook does not have all the required plugins"
            )
