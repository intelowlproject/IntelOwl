from django.db.models.signals import pre_save
from django.dispatch import receiver

from api_app.pivots_manager.models import PivotConfig


@receiver(pre_save, sender=PivotConfig)
def pre_save_pivot_config(sender, instance, raw, using, update_fields, *args, **kwargs):
    config = instance.config
    instance.description = (
        f"Pivot object for plugin {config.name}"
        f" using field {instance.field}"
        " that creates job using"
        f" playbook {instance.playbook_to_execute.name}"
    )
    instance.name = (
        f"{config.name}.{instance.field}.{instance.playbook_to_execute.name}"
    )
    return instance
