# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger

logger = getLogger(__name__)


# @receiver(post_save, sender=PluginConfig)
# def post_save_plugin_config(
#     sender, instance: PluginConfig, created: bool, raw, using, update_fields, **kwargs
# ):
#     if created:
#         logger.info(f"Invaliding config for {instance.plugin_name}")
#         instance.invalidate_method(instance.config.get_verification)
#     if instance.config_type == instance.ConfigType.SECRET:
#         instance.invalidate_method(instance.config.read_secrets)
#     elif instance.config_type == instance.ConfigType.PARAMETER:
#         instance.invalidate_method(instance.config.read_params)
#     else:
#         raise RuntimeError(f"Config type {instance.config_type} not supported")
#
#
# @receiver(pre_delete, sender=PluginConfig)
# def pre_delete_plugin_config(sender, instance: PluginConfig, using, **kwargs):
#     if instance.config_type == instance.ConfigType.SECRET:
#         instance.invalidate_method(instance.config.read_secrets)
#     elif instance.config_type == instance.ConfigType.PARAMETER:
#         instance.invalidate_method(instance.config.read_params)
#     else:
#         raise RuntimeError(f"Config type {instance.config_type} not supported")
