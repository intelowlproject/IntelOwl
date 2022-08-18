# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as BaseSerializer
from rest_framework import status
from rest_framework.response import Response

from api_app.core.views import PluginActionViewSet, PluginHealthCheckAPI
from certego_saas.ext.views import APIView

from ..models import CustomConfig
from . import controller as analyzers_controller
from .models import AnalyzerReport
from .serializers import AnalyzerConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "AnalyzerListAPI",
    "AnalyzerActionViewSet",
    "AnalyzerHealthCheckAPI",
]


class AnalyzerListAPI(APIView):

    serializer_class = AnalyzerConfigSerializer

    @add_docs(
        description="""
        Get and parse the `analyzer_config.json` file,
        can be useful if you want to choose the analyzers programmatically""",
        parameters=[],
        responses={
            200: AnalyzerConfigSerializer,
            500: inline_serializer(
                name="GetAnalyzerConfigsFailedResponse",
                fields={"error": BaseSerializer.StringRelatedField()},
            ),
        },
    )
    def get(self, request, *args, **kwargs):
        try:
            ac = self.serializer_class.read_and_verify_config()
            CustomConfig.apply(ac, request.user, CustomConfig.PluginType.ANALYZER)
            return Response(ac, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(
                f"get_analyzer_configs requester:{str(request.user)} error:{e}."
            )
            return Response(
                {"error": "error in get_analyzer_configs. Check logs."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class AnalyzerActionViewSet(PluginActionViewSet):
    queryset = AnalyzerReport.objects.all()

    @property
    def report_model(self):
        return AnalyzerReport

    def perform_kill(self, report):
        super().perform_kill(report)
        # clean up job
        analyzers_controller.job_cleanup(report.job)

    def perform_retry(self, report: AnalyzerReport):
        analyzers_to_execute, runtime_configuration = super().perform_retry(report)
        analyzers_controller.start_analyzers(
            report.job.id, analyzers_to_execute, runtime_configuration
        )


class AnalyzerHealthCheckAPI(PluginHealthCheckAPI):
    def perform_healthcheck(self, analyzer_name: str) -> bool:
        return analyzers_controller.run_healthcheck(analyzer_name)
