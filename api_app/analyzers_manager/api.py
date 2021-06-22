from rest_framework import generics
from rest_framework.response import Response

from api_app.response import helpers


class AnalyzerListAPI(generics.ListAPIView):
    def list(self, request):
        analyzers_config = helpers.get_verified_analyzer_config()

        return Response(analyzers_config)
