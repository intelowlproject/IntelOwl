# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver

from intel_owl.tasks import build_config_cache

from .models import PluginConfig


def invalidate_plugin_config(instance: PluginConfig):

    build_config_cache.delay(instance.type)
    # we are invalidating for every member of the organization
    if instance.organization:
        for member in instance.organization.members.all():
            build_config_cache.delay(instance.type, user_pk=member.user.pk)
    else:
        # only the person that created it
        build_config_cache.delay(instance.type, user_pk=instance.owner.pk)


@receiver(post_save, sender=PluginConfig)
def post_save_plugin_credential(
    sender, instance: PluginConfig, created, raw, using, update_fields, *args, **kwargs
):
    if not settings.STAGE_CI:
        invalidate_plugin_config(instance)


@receiver(pre_delete, sender=PluginConfig)
def pre_delete_plugin_credential(sender, instance, using, *args, **kwargs):
    if not settings.STAGE_CI:
        invalidate_plugin_config(instance)
