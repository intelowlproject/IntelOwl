from django.db.models.signals import pre_delete
from django.dispatch import receiver

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.visualizers_manager.models import VisualizerConfig


@receiver(pre_delete, sender=AnalyzerConfig)
@receiver(pre_delete, sender=ConnectorConfig)
@receiver(pre_delete, sender=VisualizerConfig)
def pre_delete_abstract_config(sender, instance, using, **kwargs):
    from certego_saas.apps.user.models import User

    instance.get_verification.invalidate(instance)

    for user in User.objects.all():
        instance.get_verification.invalidate(instance, user)
