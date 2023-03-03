from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver

from api_app.models import PluginConfig


@receiver(post_save, sender=PluginConfig)
def post_save_plugin_config(
    sender, instance: PluginConfig, created: bool, raw, using, update_fields, **kwargs
):
    if created:
        instance.invalidate_config_verification()


@receiver(pre_delete, sender=PluginConfig)
def pre_delete_plugin_config(sender, instance: PluginConfig, using, **kwargs):
    instance.invalidate_config_verification()
