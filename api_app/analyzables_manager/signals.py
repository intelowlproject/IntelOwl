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


@receiver(models.signals.post_save, sender=Analyzable)
def post_save_analyzable(sender, instance: Analyzable, created, **kwargs):
    if created:
        from api_app.user_events_manager.models import (
            UserDomainWildCardEvent,
            UserIPWildCardEvent,
        )

        instance.user_domain_wildcard_events.add(*UserDomainWildCardEvent.objects.matches(instance))
        instance.user_ip_wildcard_events.add(*UserIPWildCardEvent.objects.matches(instance))
