# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django_celery_beat.models import CrontabSchedule, PeriodicTask
from rest_framework import serializers as rfs

from certego_saas.apps.user.serializers import UserSerializer

from ..serializers import (
    AbstractReportSerializer,
    PythonConfigSerializer,
    PythonListConfigSerializer,
)
from .models import IngestorConfig, IngestorReport


class CrontabScheduleSerializer(rfs.ModelSerializer):
    class Meta:
        model = CrontabSchedule
        fields = [
            "minute",
            "hour",
            "day_of_week",
            "day_of_month",
            "month_of_year",
        ]


class PeriodicTaskSerializer(rfs.ModelSerializer):
    crontab = CrontabScheduleSerializer(read_only=True)

    class Meta:
        model = PeriodicTask
        fields = [
            "crontab",
            "name",
            "task",
            "kwargs",
            "queue",
            "enabled",
        ]


class IngestorConfigSerializer(PythonConfigSerializer):

    schedule = CrontabScheduleSerializer(read_only=True)
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
