from django_celery_beat.models import CrontabSchedule, PeriodicTask
from rest_framework import serializers as rfs


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
