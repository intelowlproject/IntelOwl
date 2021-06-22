from rest_framework import viewsets
from rest_framework.reponse import Response

from api_app.analyzers_manager.serializers import AnalyzerReportSerializer
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.helpers import get_analyzer_config


class AnalyzerReportViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AnalyzerReportSerializer


class AnalyzerConfigViewSet(viewsets.Viewset):
    def list(self, request):
        analyzers_config = get_analyzer_config()

        for key, config in analyzers_config.items():
            serializer = AnalyzerConfigSerializer(data=config)
            if serializer.is_valid():
                analyzers_config[key] = serializer.data

        return Response(analyzers_config)
