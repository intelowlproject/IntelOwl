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

    job = rfs.PrimaryKeyRelatedField(queryset=Job.objects.all(), write_only=True)

    class Meta:
        model = PlaybookConfig
        fields = ("name", "description", "job")

    def validate_job(self, job: Job):
        owner = self.context["request"].user
        if job.user.pk != owner.pk:
            raise ValidationError(
                "You can create a playbook from a job that you created"
            )
        return job

    def create(self, validated_data):

        job = validated_data["job"]
        types_supported = list(
            set(
                [
                    type_supported
                    for analyzer_config in job.analyzers_to_execute
                    for type_supported in analyzer_config.observable_supported
                ]
            )
        )
        if job.is_sample:
            types_supported.append(TypeChoices.FILE)
        runtime_configuration = {"analyzers": {}, "connectors": {}}
        for report in job.analyzer_reports.all():
            runtime_configuration["analyzers"][
                report.name
            ] = report.runtime_configuration
        for report in job.connector_reports.all():
            runtime_configuration["connectors"][
                report.name
            ] = report.runtime_configuration

        pc = PlaybookConfig.objects.create(
            name=validated_data["name"],
            description=validated_data["description"],
            type=types_supported,
            runtime_configuration=runtime_configuration,
        )
        pc.analyzers.set(job.analyzers_to_execute)
        pc.connectors.set(job.connectors_to_execute)
        return pc
