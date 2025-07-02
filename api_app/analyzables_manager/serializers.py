from rest_framework import serializers as rfs

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.models import Job
from api_app.serializers.job import JobRelatedField
from api_app.user_events_manager.models import UserAnalyzableEvent


class AnalyzableSerializer(rfs.ModelSerializer):
    jobs = JobRelatedField(many=True, read_only=True)
    user_events = rfs.PrimaryKeyRelatedField(many=True, read_only=True)

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
            "user_events",
        ]

    def to_representation(self, instance):
        analyzable = super().to_representation(instance)
        job = (
            Job.objects.filter(id__in=analyzable["jobs"])
            .order_by("-finished_analysis_time")
            .first()
        )
        user_event = (
            UserAnalyzableEvent.objects.filter(id__in=analyzable["user_events"])
            .order_by("-date")
            .first()
        )

        if job is None and user_event is None:
            analyzable["last_data_model"] = None
            return analyzable
        elif job is not None and user_event is not None:
            last_data_model = (
                job.data_model
                if job.data_model.date > user_event.data_model.date
                else user_event.data_model
            )
        else:
            last_data_model = (
                job.data_model if job is not None else user_event.data_model
            )

        serializer_class = Classification.get_data_model_class(
            classification=analyzable["classification"],
        ).get_serializer()
        analyzable["last_data_model"] = serializer_class(last_data_model).data
        return analyzable

    def create(self, validated_data):
        instance, _ = self.Meta.model.objects.get_or_create(**validated_data)
        return instance
