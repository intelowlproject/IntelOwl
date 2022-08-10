# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from intel_owl.tasks import build_config_cache

from .analyzers_manager.serializers import AnalyzerConfigSerializer
from .connectors_manager.serializers import ConnectorConfigSerializer
from .models import PluginCredential


@receiver(post_save, sender=PluginCredential)
def post_save_plugin_credential(*args, **kwargs):
    AnalyzerConfigSerializer.read_and_verify_config.invalidate(AnalyzerConfigSerializer)
    ConnectorConfigSerializer.read_and_verify_config.invalidate(
        ConnectorConfigSerializer
    )
    build_config_cache.delay()


@receiver(post_delete, sender=PluginCredential)
def post_delete_plugin_credential(*args, **kwargs):
    AnalyzerConfigSerializer.read_and_verify_config.invalidate(AnalyzerConfigSerializer)
    ConnectorConfigSerializer.read_and_verify_config.invalidate(
        ConnectorConfigSerializer
    )
    build_config_cache.delay()
