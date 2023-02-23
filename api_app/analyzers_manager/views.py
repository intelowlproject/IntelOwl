# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as rfs
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response

from api_app.core.views import AbstractConfigAPI, PluginActionViewSet
from intel_owl.celery import DEFAULT_QUEUE

from ..models import Job
from .models import AnalyzerConfig, AnalyzerReport
from .serializers import AnalyzerConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "AnalyzerConfigAPI",
    "AnalyzerActionViewSet",
]


class AnalyzerConfigAPI(AbstractConfigAPI):
    serializer_class = AnalyzerConfigSerializer

    @add_docs(
        description="Update plugin with latest configuration",
        request=None,
        responses={
            200: inline_serializer(
                name="PluginUpdateSuccessResponse",
                fields={
                    "status": rfs.BooleanField(allow_null=False),
                    "detail": rfs.CharField(allow_null=True),
                },
            ),
        },
    )
    @action(
        detail=True, methods=["post"], url_name="pull", permission_classes=[IsAdminUser]
    )
    def pull(self, pk):
        logger.info(f"update request from user {self.request.user}, pk {pk}")
        obj: AnalyzerConfig = self.get_object()
        success = obj.update(obj.python_path)
        if not success:
            raise ValidationError({"detail": "No update implemented"})

        return Response(data={"status": True}, status=status.HTTP_200_OK)


class AnalyzerActionViewSet(PluginActionViewSet):
    queryset = AnalyzerReport.objects.all()

    @property
    def report_model(self):
        return AnalyzerReport

    def perform_kill(self, report: AnalyzerReport):
        super().perform_kill(report)
        # clean up job
        job = Job.objects.get(pk=report.job.pk)
        job.job_cleanup()

    def perform_retry(self, report: AnalyzerReport):
        from intel_owl import tasks

        signature = AnalyzerConfig.objects.get(report.name).get_signature(
            report.job.id,
            report.runtime_configuration.get(report.name, {}),
            report.parent_playbook,
        )

        runner = signature | tasks.continue_job_pipeline.signature(
            args=[report.job.id],
            kwargs={},
            queue=DEFAULT_QUEUE,
            soft_time_limit=10,
            immutable=True,
        )
        runner()
