from django.db.models.signals import post_migrate
from django.dispatch import receiver

from api_app.analyzers_manager.apps import AnalyzersManagerConfig
from api_app.analyzers_manager.models import AnalyzerConfig


@receiver(post_migrate, sender=AnalyzersManagerConfig)
def post_migrate_analyzer(
    sender, app_config, verbosity, interactive, stdout, using, plan, apps, **kwargs
):
    if plan:
        AnalyzerConfig.delete_class_cache_keys()
