from django.db.models.signals import m2m_changed
from django.dispatch import receiver

from api_app.choices import TLP
from api_app.playbooks_manager.models import PlaybookConfig


@receiver(m2m_changed, sender=PlaybookConfig)
def m2m_changed_playbook_config(
    sender, instance: PlaybookConfig, action, reverse, model, pk_set, *args, **kwargs
):
    if action == "post_add":
        tlps = [
            TLP[x]
            for x in model.objects.filter(pk__in=pk_set).values_list(
                "maximum_tlp", flat=True
            )
        ]
        # analyzer -> amber
        # playbook -> green  => analyzer it is executed
        # --------------
        # analyzer -> amber
        # playbook -> red => analyzer it is not executed
        # ========> the playbook tlp is the minimum of all tlp of all plugins
        instance.tlp = min(tlps + [TLP[instance.tlp]], default=TLP.CLEAR).value
    return instance
