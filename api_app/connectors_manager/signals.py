from django.db.models.signals import post_migrate
from django.dispatch import receiver

from api_app.connectors_manager.apps import ConnectorsManagerConfig
from api_app.connectors_manager.models import ConnectorConfig


@receiver(post_migrate, sender=ConnectorsManagerConfig)
def post_migrate_connector(
    sender, app_config, verbosity, interactive, stdout, using, plan, apps, **kwargs
):
    if plan:
        ConnectorConfig.delete_class_cache_keys()
