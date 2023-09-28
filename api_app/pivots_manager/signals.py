from django.db.models.signals import pre_save
from django.dispatch import receiver

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
