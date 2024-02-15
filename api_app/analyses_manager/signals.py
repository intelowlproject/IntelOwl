from django.db import models
from django.dispatch import receiver

from api_app.analyses_manager.models import Analysis


@receiver(models.signals.post_save, sender=Analysis)
def post_save_python_config_cache(sender, instance: Analysis, *args, **kwargs):
    instance.delete_class_cache_keys()


@receiver(models.signals.post_delete, sender=Analysis)
def post_delete_python_config_cache(
    sender, instance: Analysis, using, origin, *args, **kwargs
):
    instance.delete_class_cache_keys()
