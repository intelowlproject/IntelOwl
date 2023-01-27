# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
import typing

from celery import group
from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as BaseSerializer
from rest_framework import status
from rest_framework.response import Response

from api_app.core.views import PluginActionViewSet, PluginHealthCheckAPI
from certego_saas.ext.views import APIView
from intel_owl.consts import DEFAULT_QUEUE

from ..models import Job, OrganizationPluginState, PluginConfig
from .dataclasses import AnalyzerConfig
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
            PluginConfig.apply(ac, request.user, PluginConfig.PluginType.ANALYZER)
            OrganizationPluginState.apply(
                ac, request.user, PluginConfig.PluginType.ANALYZER
            )
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
        job = Job.objects.get(id=report.job_id)
        job.job_cleanup()

    def perform_retry(self, report: AnalyzerReport):
        from intel_owl import tasks

        signatures, _ = AnalyzerConfig.stack(
            job_id=report.job.id,
            plugins_to_execute=[report.analyzer_name],
            runtime_configuration=report.runtime_configuration,
            parent_playbook=report.parent_playbook,
        )
        runner = group(signatures) | tasks.continue_job_pipeline.signature(
            args=[report.job.id],
            kwargs={},
            queue=DEFAULT_QUEUE,
            soft_time_limit=10,
            immutable=True,
        )
        runner()


class AnalyzerHealthCheckAPI(PluginHealthCheckAPI):
    def perform_healthcheck(self, analyzer_name: str) -> bool:
        from rest_framework.exceptions import ValidationError

        from api_app.analyzers_manager.classes import DockerBasedAnalyzer
        from api_app.core.classes import Plugin

        analyzer_config = AnalyzerConfig.get(analyzer_name)
        if analyzer_config is None:
            raise ValidationError({"detail": "Analyzer doesn't exist"})

        class_: typing.Type[Plugin] = analyzer_config.get_class()

        # docker analyzers have a common method for health check
        if not issubclass(class_, DockerBasedAnalyzer):
            raise ValidationError({"detail": "No healthcheck implemented"})

        return class_.health_check()
