from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from api_app.connectors_manager.models import ConnectorConfig


@receiver(post_save, sender=ConnectorConfig)
def post_save_connector_config(sender, instance: ConnectorConfig, *args, **kwargs):
    # delete list view cache
    instance.delete_class_cache_keys()


@receiver(post_delete, sender=ConnectorConfig)
def post_delete_connector_config(
    sender, instance: ConnectorConfig, using, origin, *args, **kwargs
):
    # delete list view cache
    instance.delete_class_cache_keys()
