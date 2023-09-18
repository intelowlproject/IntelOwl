from django.db.models.signals import pre_save
from django.dispatch import receiver

from api_app.pivots_manager.models import PivotConfig


@receiver(pre_save, sender=PivotConfig)
def pre_save_pivot_config(
    sender, instance: PivotConfig, raw, using, update_fields, *args, **kwargs
):
    instance.description = (
        f"Pivot object for plugin {str(instance.related_config.name)}"
        f"using field {instance.field_to_compare}"
        " that executes "
        f" playbook {instance.playbook_to_execute.name}"
    )
    return instance
