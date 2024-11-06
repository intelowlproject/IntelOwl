import datetime
import logging
from dataclasses import dataclass

from rest_framework import serializers

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import ReportStatus
from api_app.connectors_manager.models import ConnectorConfig
from api_app.pivots_manager.models import PivotConfig

logger = logging.getLogger(__name__)


@dataclass
class ElasticRequest:
    plugin_name: str = ""
    name: str = ""
    status: str = ""
    errors: bool = None  # different from False, we want both errors and no errors
    start_start_time: datetime.datetime = None
    end_start_time: datetime.datetime = None
    start_end_time: datetime.datetime = None
    end_end_time: datetime.datetime = None
    report: str = ""


class ElasticRequestSerializer(serializers.Serializer):
    plugin_name = serializers.ChoiceField(
        choices=[
            AnalyzerConfig.plugin_name,
            ConnectorConfig.plugin_name,
            PivotConfig.plugin_name,
        ],
        required=False,
    )
    name = serializers.CharField(required=False)
    status = serializers.ChoiceField(
        choices=ReportStatus.final_statuses(), required=False
    )
    errors = serializers.BooleanField(required=False, allow_null=True)
    start_start_time = serializers.DateTimeField(required=False)
    end_start_time = serializers.DateTimeField(required=False)
    start_end_time = serializers.DateTimeField(required=False)
    end_end_time = serializers.DateTimeField(required=False)
    report = serializers.CharField(required=False)

    def create(self, validated_data) -> ElasticRequest:
        logger.debug(f"{validated_data=}")
        return ElasticRequest(**validated_data)


class ElasticResponseSerializer(serializers.Serializer):
    job_id = serializers.IntegerField()
    plugin_name = serializers.ChoiceField(
        choices=[
            AnalyzerConfig.plugin_name,
            ConnectorConfig.plugin_name,
            PivotConfig.plugin_name,
        ],
    )
    name = serializers.CharField()
    status = serializers.ChoiceField(choices=ReportStatus.final_statuses())
    start_time = serializers.DateTimeField()
    end_time = serializers.DateTimeField()
    errors = serializers.BooleanField()
    report = serializers.CharField()
