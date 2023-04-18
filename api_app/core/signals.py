# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db.models.signals import pre_delete, pre_save
from django.dispatch import receiver

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.core.models import AbstractConfig
from api_app.visualizers_manager.models import VisualizerConfig


@receiver(pre_delete, sender=AnalyzerConfig)
@receiver(pre_delete, sender=ConnectorConfig)
@receiver(pre_delete, sender=VisualizerConfig)
def pre_delete_abstract_config(sender, instance: AbstractConfig, using, **kwargs):
    from certego_saas.apps.user.models import User

    instance.get_verification.invalidate(instance)

    for user in User.objects.all():
        instance.get_verification.invalidate(instance, user)


@receiver(pre_save, sender=AnalyzerConfig)
@receiver(pre_save, sender=ConnectorConfig)
@receiver(pre_save, sender=VisualizerConfig)
def pre_save_abstract_config(sender, instance: AbstractConfig, using, **kwargs):
    from certego_saas.apps.user.models import User

    previous = instance.__class__.objects.get(pk=instance.pk)
    instance.read_params.invalidate(instance)
    instance.read_secrets.invalidate(instance)
    if previous.params != instance.params:
        for user in User.objects.all():
            instance.read_params.invalidate(instance, user)
    if previous.secrets != instance.secrets:
        for user in User.objects.all():
            instance.read_secrets.invalidate(instance, user)
