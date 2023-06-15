from rest_framework import serializers as rfs
from rest_framework.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.core.serializers import AbstractConfigSerializer
from api_app.models import Job
from api_app.pivots_manager.models import Pivot, PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.visualizers_manager.models import VisualizerConfig


class PivotSerializer(rfs.ModelSerializer):
    starting_job = rfs.PrimaryKeyRelatedField(queryset=Job.objects.all(), required=True)
    pivot_config = rfs.PrimaryKeyRelatedField(
        queryset=PivotConfig.objects.all(), required=True
    )
    ending_job = rfs.PrimaryKeyRelatedField(queryset=Job.objects.all(), required=True)

    class Meta:
        model = Pivot
        fields = rfs.ALL_FIELDS

    def validate(self, attrs):
        result = super().validate(attrs)

        if (
            attrs["starting_job"].user.pk != self.context["request"].user.pk
            or attrs["ending_job"].user.pk != self.context["request"].user.pk
        ):
            raise ValidationError("You do not have permission to pivot these two jobs")
        return result


class PivotConfigSerializer(AbstractConfigSerializer):
    config = rfs.PrimaryKeyRelatedField(read_only=True)
    playbook_to_execute = rfs.PrimaryKeyRelatedField(
        queryset=PlaybookConfig.objects.all()
    )
    analyzer_config = rfs.PrimaryKeyRelatedField(
        write_only=True,
        queryset=AnalyzerConfig.objects.all(),
        required=False,
        default=None,
    )
    connector_config = rfs.PrimaryKeyRelatedField(
        write_only=True,
        queryset=ConnectorConfig.objects.all(),
        required=False,
        default=None,
    )
    visualizer_config = rfs.PrimaryKeyRelatedField(
        write_only=True,
        queryset=VisualizerConfig.objects.all(),
        required=False,
        default=None,
    )

    name = rfs.CharField(read_only=True)
    description = rfs.CharField(read_only=True)

    class Meta:
        model = PivotConfig
        fields = rfs.ALL_FIELDS
