import logging
import uuid

from django.conf import settings
from django.dispatch import receiver

from api_app.connectors_manager.models import ConnectorConfig
from api_app.signals import migrate_finished
from intel_owl.celery import get_queue_name

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
    from intel_owl.tasks import refresh_cache

    refresh_cache.apply_async(
        queue=get_queue_name(settings.CONFIG_QUEUE),
        MessageGroupId=str(uuid.uuid4()),
        priority=3,
        args=[ConnectorConfig.python_path],
    )
