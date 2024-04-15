import logging

from django.dispatch import receiver

from api_app.signals import migrate_finished
from api_app.visualizers_manager.models import VisualizerConfig

logger = logging.getLogger(__name__)


@receiver(migrate_finished)
def post_migrate_visualizers_manager(
    sender,
    *args,
    check_unapplied: bool = False,
    **kwargs,
):
    logger.info(f"Post migrate {args} {kwargs}")
    if check_unapplied:
        return
    VisualizerConfig.delete_class_cache_keys()
    for config in VisualizerConfig.objects.all():
        config.refresh_cache_keys()
