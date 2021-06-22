from rest_framework import viewsets

from api_app.analyzers_manager.serializers import AnalyzerReportSerializer


class AnalyzerReportViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AnalyzerReportSerializer
