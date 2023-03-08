# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer, AbstractReportSerializer

from .models import ConnectorConfig, ConnectorReport


class ConnectorConfigSerializer(AbstractConfigSerializer):
    class Meta:
        model = ConnectorConfig
        fields = rfs.ALL_FIELDS


class ConnectorReportSerializer(AbstractReportSerializer):
    class Meta:
        model = ConnectorReport
        exclude = AbstractReportSerializer.Meta.exclude
