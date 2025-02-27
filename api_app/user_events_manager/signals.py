from datetime import timedelta
from typing import Union

from django.db import models
from django.dispatch import receiver
from .models import UserDomainWildCardEvent, UserIPWildCardEvent, UserAnalyzableEvent, UserEvent



@receiver(models.signals.post_delete, sender=UserDomainWildCardEvent)
@receiver(models.signals.post_delete, sender=UserIPWildCardEvent)
@receiver(models.signals.post_delete, sender=UserAnalyzableEvent)
def post_delete_event_delete_data_model(sender, instance: UserDomainWildCardEvent, **kwargs):
    instance.data_model.delete()