# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger

from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver

from api_app.models import PluginConfig

logger = getLogger(__name__)


@receiver(post_save, sender=PluginConfig)
def post_save_plugin_config(
    sender, instance: PluginConfig, created: bool, raw, using, update_fields, **kwargs
):
    if created:
        logger.info(f"Invaliding config for {instance.plugin_name}")
        instance.invalidate_config_verification()


@receiver(pre_delete, sender=PluginConfig)
def pre_delete_plugin_config(sender, instance: PluginConfig, using, **kwargs):
    instance.invalidate_config_verification()
