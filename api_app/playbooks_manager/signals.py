from itertools import chain

from django.db.models.signals import pre_save
from django.dispatch import receiver

from api_app.choices import TLP
from api_app.playbooks_manager.models import PlaybookConfig


@receiver(pre_save, sender=PlaybookConfig)
def pre_save_playbook_config(
    sender, instance: PlaybookConfig, raw, using, update_fields, *args, **kwargs
):
    analyzers_tlps = (
        TLP[x] for x in instance.analyzers.all().values_list("maximum_tlp", flat=True)
    )
    connectors_tlps = (
        TLP[x] for x in instance.connectors.all().values_list("maximum_tlp", flat=True)
    )
    tlps = chain(analyzers_tlps, connectors_tlps)

    instance.tlp = min(tlps).value
    return instance
