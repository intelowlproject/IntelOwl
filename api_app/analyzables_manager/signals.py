from django.db import models
from django.dispatch import receiver

from api_app.analyzables_manager.models import Analyzable


@receiver(models.signals.pre_delete, sender=Analyzable)
def pre_delete_analyzable(sender, instance: Analyzable, **kwargs):
    """
    Signal receiver for the pre_delete signal of the Analyzable model.
    Deletes the associated file if it exists.

    Args:
        sender (Model): The model class sending the signal.
        instance (Analyzable): The instance of the model being deleted.
        **kwargs: Additional keyword arguments.
    """
    if instance.file:
        instance.file.delete()
