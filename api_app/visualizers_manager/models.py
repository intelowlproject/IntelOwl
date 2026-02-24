# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.contrib.contenttypes.fields import GenericRelation
from django.db import models

from api_app.choices import PythonModuleBasePaths
from api_app.decorators import classproperty
from api_app.models import AbstractReport, PythonConfig, PythonModule
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.visualizers_manager.exceptions import VisualizerConfigurationException
from api_app.visualizers_manager.queryset import VisualizerReportQuerySet
from api_app.visualizers_manager.validators import validate_report


class VisualizerReport(AbstractReport):
    objects = VisualizerReportQuerySet.as_manager()
    config = models.ForeignKey(
        "VisualizerConfig", related_name="reports", null=False, on_delete=models.CASCADE
    )
    report = models.JSONField(default=list, validators=[validate_report])
    name = models.CharField(null=True, blank=True, default=None, max_length=50)

    class Meta:
        ordering = ["pk"]
        indexes = AbstractReport.Meta.indexes


class VisualizerConfig(PythonConfig):
    playbooks = models.ManyToManyField(
        PlaybookConfig,
        related_name="visualizers",
    )
    python_module = models.ForeignKey(
        PythonModule,
        on_delete=models.PROTECT,
        related_name="%(class)ss",
        limit_choices_to={
            "base_path__in": [
                PythonModuleBasePaths.Visualizer.value,
            ]
        },
    )
    orgs_configuration = GenericRelation(
        "api_app.OrganizationPluginConfiguration", related_name="%(class)s"
    )

    @classproperty
    def plugin_type(cls) -> str:
        return "3"

    @classproperty
    def config_exception(cls):
        return VisualizerConfigurationException

    @classproperty
    def serializer_class(cls):
        from api_app.visualizers_manager.serializers import VisualizerConfigSerializer

        return VisualizerConfigSerializer
