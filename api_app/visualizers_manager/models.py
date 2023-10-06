# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import models

from api_app.models import AbstractReport, PythonConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.visualizers_manager.exceptions import VisualizerConfigurationException
from api_app.visualizers_manager.validators import validate_report


class VisualizerReport(AbstractReport):
    config = models.ForeignKey(
        "VisualizerConfig", related_name="reports", null=False, on_delete=models.CASCADE
    )
    report = models.JSONField(default=list, validators=[validate_report])
    name = models.CharField(null=True, blank=True, default=None, max_length=50)

    class Meta:
        ordering = ["pk"]


class VisualizerConfig(PythonConfig):
    playbook = models.ForeignKey(
        PlaybookConfig,
        related_name="visualizers",
        on_delete=models.CASCADE,
    )

    @classmethod
    @property
    def plugin_type(cls) -> str:
        return "3"

    @classmethod
    @property
    def config_exception(cls):
        return VisualizerConfigurationException

    @classmethod
    @property
    def serializer_class(cls):
        from api_app.visualizers_manager.serializers import VisualizerConfigSerializer

        return VisualizerConfigSerializer
