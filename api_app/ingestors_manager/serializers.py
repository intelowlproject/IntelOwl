# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from certego_saas.apps.user.serializers import UserSerializer

from ..serializers import (
    AbstractReportSerializer,
    CrontabScheduleSerializer,
    PeriodicTaskSerializer,
    PythonConfigSerializer,
    PythonListConfigSerializer,
)
from .models import IngestorConfig, IngestorReport


class IngestorConfigSerializer(PythonConfigSerializer):
    schedule = CrontabScheduleSerializer(read_only=True)

    class Meta:
        model = IngestorConfig
        exclude = ["user", "periodic_task"]
        list_serializer_class = PythonListConfigSerializer

    def to_internal_value(self, data):
        raise NotImplementedError()


class IngestorConfigSerializerForMigration(IngestorConfigSerializer):

    periodic_task = PeriodicTaskSerializer(read_only=True)
    user = UserSerializer(read_only=True)

    class Meta:
        model = IngestorConfig
        fields = rfs.ALL_FIELDS
        list_serializer_class = PythonListConfigSerializer

    def to_internal_value(self, data):
        raise NotImplementedError()


class IngestorReportSerializer(AbstractReportSerializer):
    name = rfs.SerializerMethodField()

    class Meta:
        model = IngestorReport
        fields = AbstractReportSerializer.Meta.fields

    @classmethod
    def get_name(cls, instance: IngestorReport):
        return instance.name or instance.config.pk

    def to_internal_value(self, data):
        raise NotImplementedError()
