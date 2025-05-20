from rest_framework.serializers import ModelSerializer

from api_app.analyzables_manager.models import Analyzable
from api_app.models import Job
from api_app.serializers.job import JobRelatedField


class AnalyzableSerializer(ModelSerializer):
    jobs = JobRelatedField(many=True, read_only=True)

    class Meta:
        model = Analyzable
        fields = "__all__"

    def to_representation(self, instance):
        analyzable = super().to_representation(instance)
        last_job = (
            Job.objects.filter(id__in=analyzable["jobs"])
            .order_by("-finished_analysis_time")
            .first()
        )
        analyzable["last_reliability"] = last_job.data_model.reliability
        analyzable["last_evaluation"] = last_job.data_model.evaluation
        analyzable["last_analysis"] = last_job.data_model.date
        analyzable["tags"] = last_job.data_model.tags
        analyzable["playbook_to_execute"] = last_job.playbook_to_execute.name
        return analyzable
