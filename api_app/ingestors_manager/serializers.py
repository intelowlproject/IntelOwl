# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from certego_saas.apps.user.serializers import UserSerializer

from ..playbooks_manager.models import PlaybookConfig
from ..serializers.celery import CrontabScheduleSerializer, PeriodicTaskSerializer
from ..serializers.plugin import (
    PythonConfigSerializer,
    PythonConfigSerializerForMigration,
)
from ..serializers.report import AbstractReportBISerializer, AbstractReportSerializer
from .models import IngestorConfig, IngestorReport


class IngestorConfigSerializer(PythonConfigSerializer):
    schedule = CrontabScheduleSerializer(read_only=True)
    playbook_to_execute = rfs.SlugRelatedField(
        queryset=PlaybookConfig.objects.all(), slug_field="name", many=False
    )

    class Meta:
        model = IngestorConfig
        exclude = ["user", "periodic_task"]
        list_serializer_class = PythonConfigSerializer.Meta.list_serializer_class

    def to_internal_value(self, data):
        raise NotImplementedError()


class IngestorConfigSerializerForMigration(PythonConfigSerializerForMigration):
    schedule = CrontabScheduleSerializer(read_only=True)
    periodic_task = PeriodicTaskSerializer(read_only=True)
    user = UserSerializer(read_only=True, omit=["full_name"])

    class Meta:
        model = IngestorConfig
        exclude = []

    def to_internal_value(self, data):
        raise NotImplementedError()


class IngestorReportSerializer(AbstractReportSerializer):
    name = rfs.SerializerMethodField()

    class Meta:
        model = IngestorReport
        fields = AbstractReportSerializer.Meta.fields
        list_serializer_class = AbstractReportSerializer.Meta.list_serializer_class

    @classmethod
    def get_name(cls, instance: IngestorReport):
        return instance.name or instance.config.pk

    def to_internal_value(self, data):
        raise NotImplementedError()


class IngestorReportBISerializer(AbstractReportBISerializer):
    name = rfs.SerializerMethodField()

    class Meta:
        model = IngestorReport
        fields = AbstractReportBISerializer.Meta.fields
        list_serializer_class = AbstractReportBISerializer.Meta.list_serializer_class

    @classmethod
    def get_name(cls, instance: IngestorReport):
        return instance.name or instance.config.pk
