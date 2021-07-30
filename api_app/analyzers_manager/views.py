# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework import serializers as BaseSerializer


from api_app.core.views import PluginActionViewSet
from .serializers import AnalyzerConfigSerializer
from . import controller as analyzers_controller
from .models import AnalyzerReport
from drf_spectacular.utils import (
    extend_schema as add_docs,
    inline_serializer,
)

logger = logging.getLogger(__name__)


class AnalyzerListAPI(generics.ListAPIView):
    @add_docs(
        description="""
    Get the uploaded analyzer configuration,
    can be useful if you want to choose the analyzers programmatically""",
        parameters=[],
        responses={
            200: inline_serializer(
                name="GetAnalyzerConfigsSuccessResponse",
                fields={"analyzers_config": BaseSerializer.DictField()},
            ),
            500: inline_serializer(
                name="GetAnalyzerConfigsFailedResponse",
                fields={"error": BaseSerializer.StringRelatedField()},
            ),
        },
    )
    def list(self, request):
        try:
            logger.info(
                f"get_analyzer_configs received request from {str(request.user)}."
            )
            ac = AnalyzerConfigSerializer.read_and_verify_config()
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
        super().perform_kill(self, report)
        # clean up job
        analyzers_controller.job_cleanup(report.job)

    def perform_retry(self, report: AnalyzerReport):
        analyzers_to_execute, runtime_configuration = super().perform_retry(
            self, report
        )
        analyzers_controller.start_analyzers(
            report.job.id, analyzers_to_execute, runtime_configuration
        )
