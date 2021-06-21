from rest_framework import serializers as rfs
from api_app.analyzers_manager.models import AnalyzerReport


class AnalyzerReportSerializer(rfs.ModelSerializer):
    class Meta:
        model = AnalyzerReport
        fields = "__all__"


class AnalyzerConfigSerializer(rfs.Serializer):
    name = rfs.CharField(required=True)
    type_ = rfs.CharField(required=True)
    python_module = rfs.CharField(required=True)
    description = rfs.CharField(required=True)
    disabled = rfs.BooleanField(required=True)
    secrets = rfs.JSONField(required=True)
    config = rfs.JSONField(required=True)

    def validate_secrets(self, secrets):
        pass

    def validate_config(self, config):
        pass
