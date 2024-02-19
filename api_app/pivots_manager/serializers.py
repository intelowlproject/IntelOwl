from rest_framework import serializers as rfs
from rest_framework.exceptions import ValidationError

from api_app.models import Job
from api_app.pivots_manager.models import PivotConfig, PivotMap, PivotReport
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers.plugin import (
    PythonConfigSerializer,
    PythonConfigSerializerForMigration,
)
from api_app.serializers.report import (
    AbstractReportBISerializer,
    AbstractReportSerializer,
)


class PivotReportSerializer(AbstractReportSerializer):
    class Meta:
        model = PivotReport
        fields = AbstractReportSerializer.Meta.fields
        list_serializer_class = AbstractReportSerializer.Meta.list_serializer_class


class PivotReportBISerializer(AbstractReportBISerializer):
    class Meta:
        model = PivotReport
        fields = AbstractReportBISerializer.Meta.fields
        list_serializer_class = AbstractReportBISerializer.Meta.list_serializer_class


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
            raise ValidationError(
                {"detail": "You do not have permission to pivot these two jobs"}
            )
        return result


class PivotConfigSerializer(PythonConfigSerializer):
    playbook_to_execute = rfs.SlugRelatedField(
        queryset=PlaybookConfig.objects.all(), slug_field="name"
    )

    name = rfs.CharField(read_only=True)
    description = rfs.CharField(read_only=True)
    related_configs = rfs.SlugRelatedField(read_only=True, many=True, slug_field="name")

    class Meta:
        model = PivotConfig
        exclude = ["related_analyzer_configs", "related_connector_configs"]
        list_serializer_class = PythonConfigSerializer.Meta.list_serializer_class


class PivotConfigSerializerForMigration(PythonConfigSerializerForMigration):
    related_analyzer_configs = rfs.SlugRelatedField(
        read_only=True, many=True, slug_field="name"
    )
    related_connector_configs = rfs.SlugRelatedField(
        read_only=True, many=True, slug_field="name"
    )
    playbook_to_execute = rfs.SlugRelatedField(read_only=True, slug_field="name")

    class Meta:
        model = PivotConfig
        exclude = PythonConfigSerializerForMigration.Meta.exclude
