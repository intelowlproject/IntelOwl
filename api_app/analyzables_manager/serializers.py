import logging

from rest_framework import serializers as rfs

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.models import Job
from api_app.serializers.job import JobRelatedField

logger = logging.getLogger(__name__)


class AnalyzableSerializer(rfs.ModelSerializer):
    jobs = JobRelatedField(many=True, read_only=True)

    class Meta:
        model = Analyzable
        fields = "__all__"
        read_only_fields = [
            "jobs",
            "discovery_date",
            "md5",
            "classification",
            "sha256",
            "sha1",
            "mimetype",
        ]

    def to_representation(self, instance):
        logger.debug(f"{instance=}")
        analyzable = super().to_representation(instance)
        job = (
            Job.objects.filter(id__in=analyzable["jobs"])
            .order_by("-finished_analysis_time")
            .first()
        )
        user_event_data_model = (
            instance.get_all_user_events_data_model().order_by("-date").first()
        )
        if not job and not user_event_data_model:
            analyzable["last_data_model"] = None
            return analyzable
        elif (job and job.data_model) or user_event_data_model:
            if not job or not job.data_model:
                last_data_model = user_event_data_model
            elif not user_event_data_model:
                last_data_model = job.data_model
            else:
                if (job and job.data_model) and (
                    job.data_model.date > user_event_data_model.date
                ):
                    last_data_model = job.data_model
                else:
                    last_data_model = user_event_data_model

            serializer_class = Classification.get_data_model_class(
                classification=analyzable["classification"],
            ).get_serializer()
            analyzable["last_data_model"] = serializer_class(last_data_model).data
        return analyzable

    def create(self, validated_data):
        instance, _ = self.Meta.model.objects.get_or_create(**validated_data)
        return instance
