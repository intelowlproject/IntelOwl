# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from ..serializers import (
    AbstractReportBISerializer,
    AbstractReportSerializer,
    PythonConfigSerializer,
    PythonConfigSerializerForMigration,
)
from .models import ConnectorConfig, ConnectorReport


class ConnectorConfigSerializer(PythonConfigSerializer):
    class Meta:
        model = ConnectorConfig
        exclude = PythonConfigSerializer.Meta.exclude
        list_serializer_class = PythonConfigSerializer.Meta.list_serializer_class


class ConnectorConfigSerializerForMigration(PythonConfigSerializerForMigration):
    class Meta:
        model = ConnectorConfig
        fields = PythonConfigSerializerForMigration.Meta.fields


class ConnectorReportSerializer(AbstractReportSerializer):
    class Meta:
        model = ConnectorReport
        fields = AbstractReportSerializer.Meta.fields
        list_serializer_class = AbstractReportSerializer.Meta.list_serializer_class


class ConnectorReportBISerializer(AbstractReportBISerializer):
    class Meta:
        model = ConnectorReport
        fields = AbstractReportBISerializer.Meta.fields
        list_serializer_class = AbstractReportBISerializer.Meta.list_serializer_class
