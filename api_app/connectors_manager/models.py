# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.contrib.contenttypes.fields import GenericRelation
from django.db import models

from api_app.choices import TLP, PythonModuleBasePaths
from api_app.connectors_manager.exceptions import ConnectorConfigurationException
from api_app.connectors_manager.queryset import ConnectorReportQuerySet
from api_app.decorators import classproperty
from api_app.models import AbstractReport, PythonConfig, PythonModule


class ConnectorReport(AbstractReport):
    objects = ConnectorReportQuerySet.as_manager()
    config = models.ForeignKey(
        "ConnectorConfig", related_name="reports", null=False, on_delete=models.CASCADE
    )

    class Meta:
        unique_together = [("config", "job")]
        indexes = AbstractReport.Meta.indexes


class ConnectorConfig(PythonConfig):
    maximum_tlp = models.CharField(null=False, default=TLP.CLEAR, choices=TLP.choices, max_length=50)
    run_on_failure = models.BooleanField(null=False, default=True)
    python_module = models.ForeignKey(
        PythonModule,
        on_delete=models.PROTECT,
        related_name="%(class)ss",
        limit_choices_to={"base_path": PythonModuleBasePaths.Connector.value},
    )
    orgs_configuration = GenericRelation("api_app.OrganizationPluginConfiguration", related_name="%(class)s")

    @classproperty
    def plugin_type(cls) -> str:
        return "2"

    @classproperty
    def config_exception(cls):
        return ConnectorConfigurationException

    @classproperty
    def serializer_class(cls):
        from api_app.connectors_manager.serializers import ConnectorConfigSerializer

        return ConnectorConfigSerializer
