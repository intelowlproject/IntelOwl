# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
import typing

from celery import group
from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as BaseSerializer

from api_app.core.views import (
    PluginActionViewSet,
    PluginHealthCheckAPI,
    PluginListAPI,
    PluginUpdateAPI,
)
from intel_owl.celery import DEFAULT_QUEUE

from ..models import Job
from .dataclasses import AnalyzerConfig
from .models import AnalyzerReport
from .serializers import AnalyzerConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "AnalyzerListAPI",
    "AnalyzerActionViewSet",
    "AnalyzerHealthCheckAPI",
    "AnalyzerUpdateAPI",
]


class AnalyzerListAPI(PluginListAPI):
    @property
    def serializer_class(self) -> typing.Type[AnalyzerConfigSerializer]:
        return AnalyzerConfigSerializer

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
        return super(request, *args, **kwargs)


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
    @property
    def config_model(self):
        return AnalyzerConfig


class AnalyzerUpdateAPI(PluginUpdateAPI):
    @property
    def config_model(self):
        return AnalyzerConfig
