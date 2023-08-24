# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from ..serializers import (
    AbstractReportSerializer,
    PythonConfigSerializer,
    PythonListConfigSerializer,
)
from .models import ConnectorConfig, ConnectorReport


class ConnectorConfigSerializer(PythonConfigSerializer):
    class Meta:
        model = ConnectorConfig
        exclude = ["python_module"]
        list_serializer_class = PythonListConfigSerializer


class ConnectorReportSerializer(AbstractReportSerializer):
    class Meta:
        model = ConnectorReport
        fields = AbstractReportSerializer.Meta.fields
