from typing import Type

from django.core.exceptions import ValidationError
from django.db.models.signals import m2m_changed
from django.dispatch import receiver

from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig


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
        valid_pks = (
            model.objects.filter(pk__in=pk_set)
            .valid(instance.analyzers.all(), instance.connectors.all())
            .values_list("pk", flat=True)
        )
        wrong_pks = ", ".join([str(pk) for pk in pk_set if pk not in valid_pks])
        if wrong_pks:
            raise ValidationError(
                f"You can't set pivots {wrong_pks} because"
                f" the playbook does not have all the required plugins"
            )
