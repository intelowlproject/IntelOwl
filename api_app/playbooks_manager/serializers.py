from django.core.exceptions import ValidationError
from rest_framework import serializers as rfs

from api_app.analyzers_manager.constants import TypeChoices
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig


class PlaybookConfigSerializer(rfs.ModelSerializer):
    class Meta:
        model = PlaybookConfig
        fields = rfs.ALL_FIELDS


class PlaybookConfigCreateSerializer(rfs.ModelSerializer):

    job = rfs.PrimaryKeyRelatedField(
        queryset=Job.objects.all(),
    )

    class Meta:
        model = PlaybookConfig
        fields = (
            "name",
            "description",
        )

    def validate_job(self, job: Job):
        owner = self.context["request"].user
        if job.user.pk != owner.pk:
            raise ValidationError(
                "You can create a playbook from a job that you created"
            )
        return job

    def create(self, validated_data):
        from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
        from api_app.connectors_manager.models import ConnectorConfig

        job = validated_data["job"]
        analyzers = AnalyzerConfig.objects.filter(name__in=job.analyzers_to_execute)
        connectors = ConnectorConfig.objects.filter(name__in=job.connectors_to_execute)
        types_supported = list(
            set([analyzer_config.observable_supported for analyzer_config in analyzers])
        )
        if job.is_sample:
            types_supported.append(TypeChoices.FILE)
        runtime_configuration = {}
        for report in job.analyzer_reports:
            report: AnalyzerReport
            runtime_configuration[report.name] = report.runtime_configuration
        for report in job.connector_reports:
            runtime_configuration[report.name] = report.runtime_configuration

        pc = PlaybookConfig.objects.create(
            name=validated_data["name"],
            description=validated_data["description"],
            type=types_supported,
            runtime_configuration=runtime_configuration,
        )
        pc.analyzers.set(analyzers)
        pc.connectors.set(connectors)
        return pc
