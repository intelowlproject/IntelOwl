# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver

from intel_owl.tasks import build_config_cache

from .analyzers_manager.serializers import AnalyzerConfigSerializer
from .connectors_manager.serializers import ConnectorConfigSerializer
from .models import PluginConfig


def invalidate_plugin_config(instance: PluginConfig):
    if instance.type == PluginConfig.PluginType.ANALYZER:
        serializer_class = AnalyzerConfigSerializer
    elif instance.type == PluginConfig.PluginType.CONNECTOR:
        serializer_class = ConnectorConfigSerializer
    else:
        raise TypeError(f"Unable to parse plugin type {instance.type}")

    serializer_class.read_and_verify_config.invalidate(serializer_class)
    build_config_cache.delay(serializer_class)
    # we are invalidating for every member of the organization
    if instance.organization:
        for member in instance.organization.members.all():
            serializer_class.read_and_verify_config.invalidate(
                serializer_class, member.user
            )
            build_config_cache.delay(serializer_class, member.user)
    else:
        # only the person that created it
        serializer_class.read_and_verify_config.invalidate(
            serializer_class, instance.owner
        )
        build_config_cache.delay(serializer_class, instance.owner)


@receiver(post_save, sender=PluginConfig)
def post_save_plugin_credential(
    sender, instance: PluginConfig, created, raw, using, update_fields
):
    if not settings.STAGE_CI:
        invalidate_plugin_config(instance)


@receiver(pre_delete, sender=PluginConfig)
def pre_delete_plugin_credential(sender, instance, using, origin):
    if not settings.STAGE_CI:
        invalidate_plugin_config(instance)
