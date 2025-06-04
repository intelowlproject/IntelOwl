from rest_framework import serializers as rfs

from api_app.analyzables_manager.models import Analyzable
from api_app.models import Job
from api_app.serializers.job import JobAnalyzableHistorySerializer, JobRelatedField
from api_app.user_events_manager.models import UserAnalyzableEvent
from api_app.user_events_manager.serializers import UserAnalyzableEventSerializer


class AnalyzableSerializer(rfs.ModelSerializer):
    jobs = JobRelatedField(many=True, read_only=True)
    user_events = rfs.PrimaryKeyRelatedField(many=True, read_only=True)

    class Meta:
        model = Analyzable
        fields = "__all__"

    def to_representation(self, instance):
        analyzable = super().to_representation(instance)
        jobs_queryset = Job.objects.filter(id__in=analyzable["jobs"]).order_by(
            "-finished_analysis_time"
        )
        user_events_queryset = UserAnalyzableEvent.objects.filter(
            id__in=analyzable["user_events"]
        ).order_by("-date")
        analyzable["jobs"] = JobAnalyzableHistorySerializer(
            jobs_queryset, many=True
        ).data
        analyzable["user_events"] = UserAnalyzableEventSerializer(
            user_events_queryset, many=True
        ).data
        return analyzable
