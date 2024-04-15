import logging

from django.dispatch import receiver

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.signals import migrate_finished

logger = logging.getLogger(__name__)


@receiver(migrate_finished)
def post_migrate_analyzers_manager(
    sender,
    *args,
    check_unapplied: bool = False,
    **kwargs,
):
    logger.info(f"Post migrate {args} {kwargs}")
    if check_unapplied:
        return
    AnalyzerConfig.delete_class_cache_keys()
    for config in AnalyzerConfig.objects.all():
        config.refresh_cache_keys()
