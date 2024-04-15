import logging

from django.dispatch import receiver

from api_app.connectors_manager.models import ConnectorConfig
from api_app.signals import migrate_finished

logger = logging.getLogger(__name__)


@receiver(migrate_finished)
def post_migrate_connectors_manager(
    sender,
    *args,
    check_unapplied: bool = False,
    **kwargs,
):
    logger.info(f"Post migrate {args} {kwargs}")
    if check_unapplied:
        return
    ConnectorConfig.delete_class_cache_keys()
    for config in ConnectorConfig.objects.all():
        config.refresh_cache_keys()
