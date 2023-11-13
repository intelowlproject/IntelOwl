from django.db.models.signals import post_migrate
from django.dispatch import receiver

from api_app.visualizers_manager.apps import VisualizersManagerConfig
from api_app.visualizers_manager.models import VisualizerConfig


@receiver(post_migrate, sender=VisualizersManagerConfig)
def post_migrate_visualizer(
    sender, app_config, verbosity, interactive, stdout, using, plan, apps, **kwargs
):
    if plan:
        VisualizerConfig.delete_class_cache_keys()
