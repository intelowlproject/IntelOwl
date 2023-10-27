from rest_framework import serializers as rfs
from rest_framework.exceptions import ValidationError

from api_app.models import Job
from api_app.pivots_manager.models import PivotConfig, PivotMap, PivotReport
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers import (
    AbstractReportSerializer,
    PythonConfigSerializer,
    PythonConfigSerializerForMigration,
)


class PivotReportSerializer(AbstractReportSerializer):
    class Meta:
        model = PivotReport
        fields = AbstractReportSerializer.Meta.fields


class PivotMapSerializer(rfs.ModelSerializer):
    starting_job = rfs.PrimaryKeyRelatedField(queryset=Job.objects.all(), required=True)
    pivot_config = rfs.PrimaryKeyRelatedField(
        queryset=PivotConfig.objects.all(), required=True
    )
    ending_job = rfs.PrimaryKeyRelatedField(queryset=Job.objects.all(), required=True)

    class Meta:
        model = PivotMap
        fields = rfs.ALL_FIELDS

    def validate(self, attrs):
        result = super().validate(attrs)

        if (
            result["starting_job"].user.pk != self.context["request"].user.pk
            or result["ending_job"].user.pk != self.context["request"].user.pk
        ):
            raise ValidationError("You do not have permission to pivot these two jobs")
        return result


class PivotConfigSerializer(PythonConfigSerializer):
    playbook_to_execute = rfs.PrimaryKeyRelatedField(
        queryset=PlaybookConfig.objects.all()
    )

    name = rfs.CharField(read_only=True)
    description = rfs.CharField(read_only=True)
    related_configs = rfs.PrimaryKeyRelatedField(read_only=True, many=True)

    class Meta:
        model = PivotConfig
        exclude = ["related_analyzer_configs", "related_connector_configs"]
        list_serializer_class = PythonConfigSerializer.Meta.list_serializer_class


class PivotConfigSerializerForMigration(PythonConfigSerializerForMigration):
    class Meta:
        model = PivotConfig
        exclude = PythonConfigSerializerForMigration.Meta.exclude
