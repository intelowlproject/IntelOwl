from rest_framework.serializers import ModelSerializer

from api_app.analyzables_manager.models import Analyzable
from api_app.serializers.job import JobRelatedField


class AnalyzableSerializer(ModelSerializer):
    jobs = JobRelatedField(many=True, read_only=True)

    class Meta:
        model = Analyzable
        fields = "__all__"
