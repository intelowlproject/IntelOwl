from rest_framework import serializers as rfs
from api_app.analyzers_manager.models import Analyzer


class AnalyzerSerializer(rfs.ModelSerializer):
    class Meta:
        model = Analyzer

    verification = rfs.SerializerMethodField()

    def get_verification(self, obj: Analyzer):
        return obj.verify_secrets()
