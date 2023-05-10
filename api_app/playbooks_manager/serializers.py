# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import django.core.exceptions
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

    @staticmethod
    def create(validated_data):

        job = validated_data["job"]
        types_supported = list(
            set(
                [
                    type_supported
                    for analyzer_config in job.analyzers_to_execute.all()
                    for type_supported in analyzer_config.observable_supported
                ]
            )
        )
        if job.is_sample:
            types_supported.append(TypeChoices.FILE)

        pc = PlaybookConfig(
            name=validated_data["name"],
            description=validated_data["description"],
            type=types_supported,
            runtime_configuration=job.runtime_configuration,
        )
        try:
            pc.full_clean()
        except django.core.exceptions.ValidationError as e:
            raise ValidationError(e)
        pc.save()
        pc.analyzers.set(list(job.analyzers_to_execute.all()))
        pc.connectors.set(list(job.connectors_to_execute.all()))
        return pc
